"""Tests for CIS Benchmark edition auto-detection (Win10 v4.0.0 / Win11 v5.0.0).

Covers the three layers:
  - cis_map.benchmark_version  — the OS-family → edition mapping (source of truth)
  - Scanner.run                — stamps the right edition from build detection
  - Reporter HTML footer       — displays the edition the scan actually used
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from apotrope import cis_map
from apotrope.models import AuditReport, CheckResult, Severity, Status
from apotrope.reporter import Reporter
from apotrope.scanner import Scanner


# ---------------------------------------------------------------------------
# cis_map.benchmark_version — the mapping
# ---------------------------------------------------------------------------

class TestBenchmarkVersion:
    def test_win11_is_v5(self):
        assert cis_map.benchmark_version(cis_map.OSFamily.WIN11) == "v5.0.0"

    def test_win10_is_v4(self):
        assert cis_map.benchmark_version(cis_map.OSFamily.WIN10) == "v4.0.0"

    def test_default_is_win11(self):
        assert cis_map.benchmark_version() == "v5.0.0"

    def test_server_2022_is_v4_baseline_with_caveat(self):
        # Best-effort: Server 2022 rides the Win10 v4.0.0 baseline and is
        # flagged with a caveat until its own benchmark IDs are sourced.
        assert cis_map.benchmark_version(cis_map.OSFamily.SERVER_2022) == "v4.0.0"
        assert cis_map.benchmark_caveat(cis_map.OSFamily.SERVER_2022)       # non-empty
        assert cis_map.benchmark_caveat(cis_map.OSFamily.WIN11) == ""        # exact → none

    def test_family_for_build(self):
        assert cis_map.family_for_build(20348) == cis_map.OSFamily.SERVER_2022
        assert cis_map.family_for_build(22631) == cis_map.OSFamily.WIN11
        assert cis_map.family_for_build(22000) == cis_map.OSFamily.WIN11
        assert cis_map.family_for_build(19045) == cis_map.OSFamily.WIN10

    def test_family_for_build_disambiguates_server_by_product_type(self):
        # Builds 17763 / 14393 are shared by client Windows and a Server SKU.
        # ProductType (1=Workstation, 2=Domain Controller, 3=Server) is what
        # tells them apart — without it, both look like the Win10 baseline.
        assert cis_map.family_for_build(17763, 1) == cis_map.OSFamily.WIN10
        assert cis_map.family_for_build(17763, 2) == cis_map.OSFamily.SERVER_2019
        assert cis_map.family_for_build(17763, 3) == cis_map.OSFamily.SERVER_2019
        assert cis_map.family_for_build(14393, 1) == cis_map.OSFamily.WIN10
        assert cis_map.family_for_build(14393, 2) == cis_map.OSFamily.SERVER_2016
        assert cis_map.family_for_build(14393, 3) == cis_map.OSFamily.SERVER_2016

    def test_family_for_build_product_type_none_falls_back_to_build(self):
        # No ProductType available → shared server builds classify as Win10.
        assert cis_map.family_for_build(17763) == cis_map.OSFamily.WIN10
        assert cis_map.family_for_build(14393) == cis_map.OSFamily.WIN10

    def test_family_for_build_20348_is_server_2022_regardless_of_product_type(self):
        # 20348 ships only on Server 2022 — unambiguous with or without ProductType.
        assert cis_map.family_for_build(20348, None) == cis_map.OSFamily.SERVER_2022
        assert cis_map.family_for_build(20348, 1) == cis_map.OSFamily.SERVER_2022
        assert cis_map.family_for_build(20348, 3) == cis_map.OSFamily.SERVER_2022

    def test_server_2016_2019_are_v4_baseline_with_caveat(self):
        # Both ride the Win10 v4.0.0 baseline as a best-effort and must say so —
        # a reachable server family with no caveat would be a silent Win10 stamp.
        for fam in (cis_map.OSFamily.SERVER_2016, cis_map.OSFamily.SERVER_2019):
            assert cis_map.benchmark_version(fam) == "v4.0.0"
            assert cis_map.benchmark_caveat(fam)  # non-empty best-effort caveat

    def test_constants_match(self):
        assert cis_map.CIS_VERSION_WIN11 == "v5.0.0"
        assert cis_map.CIS_VERSION_WIN10 == "v4.0.0"


# ---------------------------------------------------------------------------
# cis_map.lookup — per-check IDs still switch by OS family
# ---------------------------------------------------------------------------

class TestLookupOsAware:
    def test_win11_uses_base_id(self):
        # Win11 v5.0.0 base map ID for PowerShell script-block logging.
        assert cis_map.lookup("PowerShell Script Block Logging") == "CIS 18.10.88.1"

    def test_win10_substitutes_override(self):
        # Win10 v4.0.0 renumbers section 88 → 87, so the ID must differ.
        win10 = cis_map.lookup("PowerShell Script Block Logging", cis_map.OSFamily.WIN10)
        win11 = cis_map.lookup("PowerShell Script Block Logging", cis_map.OSFamily.WIN11)
        assert win10 == "CIS 18.10.87.1"
        assert win10 != win11

    def test_server_2022_uses_v4_baseline_ids(self):
        # Server 2022 shares the Win10 v4.0.0 override set as its best-effort baseline.
        srv = cis_map.lookup("PowerShell Script Block Logging", cis_map.OSFamily.SERVER_2022)
        assert srv == "CIS 18.10.87.1"


# ---------------------------------------------------------------------------
# Scanner stamps cis_version from the same build detection it uses for IDs
# ---------------------------------------------------------------------------

def _fake_module() -> ModuleType:
    # setattr (not mod.attr =) so mypy accepts dynamic attributes on ModuleType.
    mod = ModuleType("fake")
    setattr(mod, "CATEGORY", "Test")
    setattr(mod, "run", lambda: [CheckResult("Test", "x", Status.PASS, Severity.LOW, "d", "ok")])
    return mod


def _run_with_build(build_version: str, product_type: int | None = 1) -> AuditReport:
    # product_type defaults to 1 (Workstation) so the existing client-Windows
    # cases are unaffected; server cases pass 2 (Domain Controller) or 3 (Server).
    scanner = Scanner()
    with patch("apotrope.scanner.platform.version", return_value=build_version), \
         patch.object(scanner, "_discover_modules", return_value=[_fake_module()]), \
         patch.object(scanner, "_detect_product_type", return_value=product_type):
        return scanner.run()


class TestScannerStampsVersion:
    def test_win11_build_stamps_v5(self):
        report = _run_with_build("10.0.22631")  # Win11
        assert report.cis_version == "v5.0.0"

    def test_win10_build_stamps_v4(self):
        report = _run_with_build("10.0.19045")  # Win10 22H2
        assert report.cis_version == "v4.0.0"

    def test_boundary_22000_is_win11(self):
        report = _run_with_build("10.0.22000")  # first Win11 build
        assert report.cis_version == "v5.0.0"

    def test_server_2022_build_stamps_v4_with_caveat(self):
        report = _run_with_build("10.0.20348")  # Server 2022 (unambiguous build)
        assert report.cis_version == "v4.0.0"
        assert report.cis_caveat  # honest best-effort caveat, not a silent Win10 stamp

    def test_server_2019_build_stamps_v4_with_caveat(self):
        # Same build as Win10 1809 — ProductType 3 (Server) is what makes it 2019.
        report = _run_with_build("10.0.17763", product_type=3)
        assert report.cis_version == "v4.0.0"
        assert report.cis_caveat  # best-effort, not a silent Win10 stamp

    def test_win10_1809_same_build_no_caveat(self):
        # Build 17763 with Workstation ProductType stays client Win10 (exact, no caveat).
        report = _run_with_build("10.0.17763", product_type=1)
        assert report.cis_version == "v4.0.0"
        assert not report.cis_caveat

    def test_server_2016_build_stamps_v4_with_caveat(self):
        # Build 14393 with Domain Controller ProductType → Server 2016 best-effort.
        report = _run_with_build("10.0.14393", product_type=2)
        assert report.cis_version == "v4.0.0"
        assert report.cis_caveat


# ---------------------------------------------------------------------------
# Scanner._detect_product_type — WMI ProductType used to disambiguate servers
# ---------------------------------------------------------------------------

class TestDetectProductType:
    def test_returns_int_product_type(self):
        with patch("apotrope.scanner.get_wmi_object", return_value=[{"ProductType": 3}]):
            assert Scanner._detect_product_type() == 3

    def test_none_when_wmi_returns_no_rows(self):
        # get_wmi_object returns [] on non-Windows / access-denied / class-missing.
        with patch("apotrope.scanner.get_wmi_object", return_value=[]):
            assert Scanner._detect_product_type() is None

    def test_none_when_product_type_absent_or_non_int(self):
        with patch("apotrope.scanner.get_wmi_object", return_value=[{"ProductType": None}]):
            assert Scanner._detect_product_type() is None


# ---------------------------------------------------------------------------
# Reporter HTML footer shows the detected edition
# ---------------------------------------------------------------------------

def _render(report: AuditReport) -> str:
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
        path = f.name
    try:
        Reporter().generate_html_report(report, path)
        return Path(path).read_text(encoding="utf-8")
    finally:
        os.unlink(path)


def _report(
    cis_version: str = "",
    os_version: str = "Windows 11 Pro 10.0.22631",
    cis_caveat: str = "",
) -> AuditReport:
    return AuditReport(
        hostname="PC",
        os_version=os_version,
        scan_timestamp=datetime(2026, 6, 6, tzinfo=timezone.utc),
        scan_duration=1.0,
        results=[CheckResult("Firewall", "FW", Status.PASS, Severity.LOW, "d", "ok")],
        score=100,
        cis_version=cis_version,
        cis_caveat=cis_caveat,
    )


class TestReporterFooterVersion:
    def test_uses_stamped_version_win10(self):
        html = _render(_report(cis_version="v4.0.0"))
        assert "CIS Benchmark v4.0.0" in html
        assert "v5.0.0" not in html

    def test_uses_stamped_version_win11(self):
        html = _render(_report(cis_version="v5.0.0"))
        assert "CIS Benchmark v5.0.0" in html

    def test_fallback_parses_win10_build(self):
        # No stamped version → infer from the build in os_version.
        html = _render(_report(cis_version="", os_version="Windows 10 Pro 10.0.19045"))
        assert "CIS Benchmark v4.0.0" in html

    def test_fallback_parses_win11_build(self):
        html = _render(_report(cis_version="", os_version="Windows 11 Pro 10.0.26100"))
        assert "CIS Benchmark v5.0.0" in html

    def test_fallback_unparseable_build_defaults_win11(self):
        # os_version with no trailing build number → treat as current (Win11).
        html = _render(_report(cis_version="", os_version="Windows (unknown build)"))
        assert "CIS Benchmark v5.0.0" in html

    def test_caveat_rendered_when_present(self):
        html = _render(_report(cis_version="v4.0.0", cis_caveat="Server 2022 best-effort"))
        assert "Server 2022 best-effort" in html

    def test_no_caveat_when_absent(self):
        html = _render(_report(cis_version="v5.0.0"))
        assert "best-effort" not in html
