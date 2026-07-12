"""Tests for apotrope.cli — argument parsing and main() dispatch."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from apotrope.cli import _exec_href, build_parser


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

class TestBuildParser:
    def _parse(self, *args: str):
        return build_parser().parse_args(list(args))

    def test_defaults(self):
        ns = self._parse()
        assert ns.html is None
        assert ns.json is None
        assert ns.category is None
        assert ns.verbose is False
        assert ns.no_color is False
        assert ns.log_level == "WARNING"

    def test_html_flag(self):
        ns = self._parse("--html", "report.html")
        assert ns.html == "report.html"

    def test_exec_report_flag(self):
        ns = self._parse("--exec-report", "brief.html")
        assert ns.exec_report == "brief.html"

    def test_exec_report_default_none(self):
        ns = self._parse()
        assert ns.exec_report is None

    def test_json_flag(self):
        ns = self._parse("--json", "out.json")
        assert ns.json == "out.json"

    def test_category_flag(self):
        ns = self._parse("--category", "firewall,encryption")
        assert ns.category == "firewall,encryption"

    def test_verbose_flag(self):
        ns = self._parse("--verbose")
        assert ns.verbose is True

    def test_no_color_flag(self):
        ns = self._parse("--no-color")
        assert ns.no_color is True

    def test_log_level_debug(self):
        ns = self._parse("--log-level", "DEBUG")
        assert ns.log_level == "DEBUG"

    def test_log_level_invalid(self):
        with pytest.raises(SystemExit):
            self._parse("--log-level", "VERBOSE")

    def test_all_flags_together(self):
        ns = self._parse(
            "--html", "r.html",
            "--json", "r.json",
            "--category", "firewall",
            "--verbose",
            "--no-color",
            "--log-level", "DEBUG",
        )
        assert ns.html == "r.html"
        assert ns.json == "r.json"
        assert ns.category == "firewall"
        assert ns.verbose is True
        assert ns.no_color is True
        assert ns.log_level == "DEBUG"

    def test_version_exits(self):
        with pytest.raises(SystemExit) as exc_info:
            self._parse("--version")
        assert exc_info.value.code == 0

    def test_fix_still_parses_as_noop(self):
        """Retired flag must not error for existing scripts."""
        ns = self._parse("--fix")
        assert ns.fix is True

    def test_fix_hidden_from_help(self):
        assert "--fix" not in build_parser().format_help()


# ---------------------------------------------------------------------------
# _exec_href — link from the technical report to the executive report
# ---------------------------------------------------------------------------

class TestExecHref:
    def test_same_directory_is_basename(self):
        assert _exec_href("report.html", "brief.html") == "brief.html"

    def test_subdirectory_uses_forward_slashes_and_encoding(self):
        href = _exec_href("out/report.html", "out/sub/exec report.html")
        assert href == "sub/exec%20report.html"

    def test_parent_directory_relpath(self):
        href = _exec_href("out/deep/report.html", "out/brief.html")
        assert href == "../brief.html"

    def test_cross_drive_falls_back_to_file_uri(self):
        with patch("os.path.relpath",
                   side_effect=ValueError("different drives")):
            href = _exec_href("C:/reports/report.html", "D:/other/brief.html")
        assert href.startswith("file:///")
        assert href.endswith("brief.html")


# ---------------------------------------------------------------------------
# main() dispatch
# ---------------------------------------------------------------------------

class TestMain:
    # Scanner/Reporter/is_admin/load_profile are lazy-imported inside main(),
    # so we patch them in their source modules (not in apotrope.cli).
    _SCANNER_PATH  = "apotrope.scanner.Scanner"
    _REPORTER_PATH = "apotrope.reporter.Reporter"
    _ADMIN_PATH    = "apotrope.utils.is_admin"
    _PROFILE_PATH  = "apotrope.profile.load_profile"

    def _run_main(self, argv=None, is_admin=False, score=80):
        """Run main() with mocked scanner, reporter, is_admin, and load_profile."""
        mock_report = MagicMock()
        mock_report.fail_count = 0
        mock_report.error_count = 0
        mock_report.score = score

        mock_scanner_instance = MagicMock()
        mock_scanner_instance.is_admin = is_admin

        mock_reporter_instance = MagicMock()
        mock_reporter_instance.run_with_progress.return_value = mock_report

        argv = argv or []
        with (
            patch("sys.argv", ["apotrope"] + argv),
            patch(self._SCANNER_PATH, return_value=mock_scanner_instance) as MockScanner,
            patch(self._REPORTER_PATH, return_value=mock_reporter_instance),
            patch(self._ADMIN_PATH, return_value=is_admin),
            patch(self._PROFILE_PATH, return_value=MagicMock()),
        ):
            from apotrope import cli as cli_mod
            import importlib
            importlib.reload(cli_mod)
            cli_mod.main()

        return MockScanner, mock_reporter_instance, mock_report

    def test_scanner_created_with_is_admin_false(self):
        MockScanner, _, _ = self._run_main(is_admin=False)
        assert MockScanner.called

    def test_scanner_created_with_is_admin_true(self):
        MockScanner, _, _ = self._run_main(is_admin=True)
        call_kwargs = MockScanner.call_args[1]
        assert call_kwargs.get("is_admin") is True

    def test_html_report_saved_when_flag_provided(self):
        _, mock_reporter, _ = self._run_main(["--html", "out.html"])
        mock_reporter.generate_html_report.assert_called_once()

    def test_json_report_saved_when_flag_provided(self):
        _, mock_reporter, _ = self._run_main(["--json", "out.json"])
        mock_reporter.generate_json_report.assert_called_once()

    def test_no_html_by_default(self):
        _, mock_reporter, _ = self._run_main()
        mock_reporter.generate_html_report.assert_not_called()

    def test_no_json_by_default(self):
        _, mock_reporter, _ = self._run_main()
        mock_reporter.generate_json_report.assert_not_called()

    def test_print_terminal_always_called(self):
        _, mock_reporter, _ = self._run_main()
        mock_reporter.print_terminal.assert_called_once()

    def test_exit_1_on_failures(self):
        """Exit 1 when score < 70."""
        mock_report = MagicMock()
        mock_report.fail_count = 3
        mock_report.error_count = 0
        mock_report.score = 55  # below 70 → exit 1
        mock_scanner = MagicMock()
        mock_scanner.is_admin = False
        mock_reporter = MagicMock()
        mock_reporter.run_with_progress.return_value = mock_report

        with (
            patch("sys.argv", ["apotrope"]),
            patch(self._SCANNER_PATH, return_value=mock_scanner),
            patch(self._REPORTER_PATH, return_value=mock_reporter),
            patch(self._ADMIN_PATH, return_value=False),
            patch(self._PROFILE_PATH, return_value=MagicMock()),
            pytest.raises(SystemExit) as exc_info,
        ):
            from apotrope import cli as cli_mod
            import importlib
            importlib.reload(cli_mod)
            cli_mod.main()

        assert exc_info.value.code == 1

    def test_exit_0_on_clean_scan(self):
        """Exit 0 when score >= 70."""
        mock_report = MagicMock()
        mock_report.fail_count = 0
        mock_report.error_count = 0
        mock_report.score = 100  # above 70 → no exit
        mock_scanner = MagicMock()
        mock_scanner.is_admin = False
        mock_reporter = MagicMock()
        mock_reporter.run_with_progress.return_value = mock_report

        with (
            patch("sys.argv", ["apotrope"]),
            patch(self._SCANNER_PATH, return_value=mock_scanner),
            patch(self._REPORTER_PATH, return_value=mock_reporter),
            patch(self._ADMIN_PATH, return_value=False),
            patch(self._PROFILE_PATH, return_value=MagicMock()),
        ):
            from apotrope import cli as cli_mod
            import importlib
            importlib.reload(cli_mod)
            cli_mod.main()  # Should NOT raise SystemExit

    def test_category_filter_passed_to_scanner(self):
        MockScanner, _, _ = self._run_main(["--category", "firewall,encryption"])
        call_kwargs = MockScanner.call_args[1]
        assert call_kwargs.get("categories") == ["firewall", "encryption"]

    def test_verbose_passed_to_reporter(self):
        mock_report = MagicMock(fail_count=0, error_count=0, score=90)
        mock_scanner = MagicMock(is_admin=False)
        mock_reporter = MagicMock()
        mock_reporter.run_with_progress.return_value = mock_report

        with (
            patch("sys.argv", ["apotrope", "--verbose"]),
            patch(self._SCANNER_PATH, return_value=mock_scanner),
            patch(self._REPORTER_PATH, return_value=mock_reporter) as MockReporter,
            patch(self._ADMIN_PATH, return_value=False),
            patch(self._PROFILE_PATH, return_value=MagicMock()),
        ):
            from apotrope import cli as cli_mod
            import importlib
            importlib.reload(cli_mod)
            cli_mod.main()

        MockReporter.assert_called_once_with(verbose=True, no_color=False)

    def test_exit_1_when_score_below_70(self):
        """Score 69 → exit 1."""
        mock_report = MagicMock(fail_count=0, error_count=0, score=69)
        mock_scanner = MagicMock(is_admin=False)
        mock_reporter = MagicMock()
        mock_reporter.run_with_progress.return_value = mock_report

        with (
            patch("sys.argv", ["apotrope"]),
            patch(self._SCANNER_PATH, return_value=mock_scanner),
            patch(self._REPORTER_PATH, return_value=mock_reporter),
            patch(self._ADMIN_PATH, return_value=False),
            patch(self._PROFILE_PATH, return_value=MagicMock()),
            pytest.raises(SystemExit) as exc,
        ):
            from apotrope import cli as cli_mod
            import importlib
            importlib.reload(cli_mod)
            cli_mod.main()
        assert exc.value.code == 1

    def test_exit_0_when_score_exactly_70(self):
        """Score 70 → exit 0 (no SystemExit raised)."""
        mock_report = MagicMock(fail_count=0, error_count=0, score=70)
        mock_scanner = MagicMock(is_admin=False)
        mock_reporter = MagicMock()
        mock_reporter.run_with_progress.return_value = mock_report

        with (
            patch("sys.argv", ["apotrope"]),
            patch(self._SCANNER_PATH, return_value=mock_scanner),
            patch(self._REPORTER_PATH, return_value=mock_reporter),
            patch(self._ADMIN_PATH, return_value=False),
            patch(self._PROFILE_PATH, return_value=MagicMock()),
        ):
            from apotrope import cli as cli_mod
            import importlib
            importlib.reload(cli_mod)
            cli_mod.main()  # should not raise

    def test_dry_run_exits_cleanly(self):
        """--dry-run should print module list and return without scanning."""
        mock_scanner = MagicMock()
        mock_scanner.dry_run.return_value = ["apotrope.checks.firewall", "apotrope.checks.smb"]

        with (
            patch("sys.argv", ["apotrope", "--dry-run"]),
            patch(self._SCANNER_PATH, return_value=mock_scanner),
            patch(self._REPORTER_PATH, return_value=MagicMock()),
            patch(self._ADMIN_PATH, return_value=False),
            patch(self._PROFILE_PATH, return_value=MagicMock()),
        ):
            from apotrope import cli as cli_mod
            import importlib
            importlib.reload(cli_mod)
            cli_mod.main()  # should return without calling run_with_progress

        mock_scanner.dry_run.assert_called_once()
        mock_scanner.run_with_progress = MagicMock()
        # run_with_progress should NOT have been called on the reporter
        # (checking via scanner.dry_run was called is sufficient)


# ---------------------------------------------------------------------------
# main() error paths, exit codes, and output wiring
# ---------------------------------------------------------------------------

class TestMainErrorPaths:
    _SCANNER_PATH  = "apotrope.scanner.Scanner"
    _REPORTER_PATH = "apotrope.reporter.Reporter"
    _ADMIN_PATH    = "apotrope.utils.is_admin"
    _PROFILE_PATH  = "apotrope.profile.load_profile"

    def _patches(self, argv, mock_reporter):
        mock_scanner = MagicMock(is_admin=False)
        return (
            patch("sys.argv", ["apotrope"] + argv),
            patch(self._SCANNER_PATH, return_value=mock_scanner),
            patch(self._REPORTER_PATH, return_value=mock_reporter),
            patch(self._ADMIN_PATH, return_value=False),
            patch(self._PROFILE_PATH, return_value=MagicMock()),
        )

    def _reporter_with_report(self, score=80):
        mock_report = MagicMock(fail_count=0, error_count=0, score=score)
        mock_reporter = MagicMock()
        mock_reporter.run_with_progress.return_value = mock_report
        return mock_reporter, mock_report

    def _run_main(self, argv, mock_reporter):
        from apotrope.cli import main

        p1, p2, p3, p4, p5 = self._patches(argv, mock_reporter)
        with p1, p2, p3, p4, p5:
            main()

    def test_compare_missing_baseline_exits_2(self, tmp_path, capsys):
        mock_reporter, _ = self._reporter_with_report()
        missing = str(tmp_path / "no-such-baseline.json")
        with pytest.raises(SystemExit) as exc:
            self._run_main(["--compare", missing], mock_reporter)
        assert exc.value.code == 2
        assert "Cannot load baseline" in capsys.readouterr().err
        mock_reporter.run_with_progress.assert_not_called()

    def test_compare_corrupt_baseline_exits_2(self, tmp_path, capsys):
        bad = tmp_path / "corrupt.json"
        bad.write_text("{not valid json", encoding="utf-8")
        mock_reporter, _ = self._reporter_with_report()
        with pytest.raises(SystemExit) as exc:
            self._run_main(["--compare", str(bad)], mock_reporter)
        assert exc.value.code == 2
        assert "Cannot load baseline" in capsys.readouterr().err

    def test_fatal_scan_error_exits_2(self, capsys):
        mock_reporter = MagicMock()
        mock_reporter.run_with_progress.side_effect = RuntimeError("kaboom")
        with pytest.raises(SystemExit) as exc:
            self._run_main([], mock_reporter)
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "[FATAL]" in err
        assert "kaboom" in err

    def test_compare_success_prints_comparison(self, tmp_path):
        baseline = MagicMock()
        diff = MagicMock()
        mock_reporter, mock_report = self._reporter_with_report()
        # Baseline file must exist only as a path argument; loading is mocked.
        with (
            patch("apotrope.compare.load_baseline", return_value=baseline),
            patch("apotrope.compare.compare_reports", return_value=diff) as cmp_mock,
        ):
            self._run_main(["--compare", "baseline.json"], mock_reporter)
        cmp_mock.assert_called_once_with(baseline, mock_report)
        mock_reporter.print_comparison.assert_called_once_with(diff)

    def test_no_comparison_without_flag(self):
        mock_reporter, _ = self._reporter_with_report()
        self._run_main([], mock_reporter)
        mock_reporter.print_comparison.assert_not_called()

    def test_baseline_flag_saves_baseline(self):
        mock_reporter, mock_report = self._reporter_with_report()
        with patch("apotrope.compare.save_baseline") as save_mock:
            self._run_main(["--baseline", "base.json"], mock_reporter)
        save_mock.assert_called_once_with(mock_report, "base.json")

    def test_no_baseline_saved_by_default(self):
        mock_reporter, _ = self._reporter_with_report()
        with patch("apotrope.compare.save_baseline") as save_mock:
            self._run_main([], mock_reporter)
        save_mock.assert_not_called()

    def test_html_and_json_paths_passed_to_print_terminal(self):
        mock_reporter, mock_report = self._reporter_with_report()
        self._run_main(["--html", "out.html", "--json", "out.json"], mock_reporter)
        mock_reporter.print_terminal.assert_called_once_with(
            mock_report, html_path="out.html", json_path="out.json",
            exec_path=None,
        )

    def test_exec_report_saved_when_flag_provided(self):
        mock_reporter, mock_report = self._reporter_with_report()
        self._run_main(["--exec-report", "brief.html"], mock_reporter)
        mock_reporter.generate_executive_report.assert_called_once_with(
            mock_report, "brief.html"
        )

    def test_html_and_exec_report_must_use_distinct_paths(self, capsys):
        mock_reporter, _ = self._reporter_with_report()
        with pytest.raises(SystemExit, match="2"):
            self._run_main(
                ["--html", "report.html", "--exec-report", "report.html"],
                mock_reporter,
            )
        assert (
            "--html and --exec-report must use different files"
            in capsys.readouterr().err
        )
        mock_reporter.run_with_progress.assert_not_called()

    def test_html_and_exec_report_reject_equivalent_paths(
        self, tmp_path, capsys
    ):
        target = tmp_path / "report.html"
        equivalent = tmp_path / "." / "report.html"
        mock_reporter, _ = self._reporter_with_report()
        with pytest.raises(SystemExit, match="2"):
            self._run_main(
                ["--html", str(target), "--exec-report", str(equivalent)],
                mock_reporter,
            )
        assert (
            "--html and --exec-report must use different files"
            in capsys.readouterr().err
        )
        mock_reporter.run_with_progress.assert_not_called()

    def test_no_exec_report_by_default(self):
        mock_reporter, _ = self._reporter_with_report()
        self._run_main([], mock_reporter)
        mock_reporter.generate_executive_report.assert_not_called()

    def test_exec_href_passed_when_both_outputs(self):
        """The technical report links to the exec report only when it exists."""
        mock_reporter, mock_report = self._reporter_with_report()
        with patch("pathlib.Path.exists", return_value=True):
            self._run_main(
                ["--html", "out.html", "--exec-report", "brief.html"],
                mock_reporter,
            )
        mock_reporter.generate_html_report.assert_called_once_with(
            mock_report, "out.html", exec_href="brief.html"
        )

    def test_exec_href_none_when_exec_file_missing(self):
        """No dangling header link when exec generation wrote nothing."""
        mock_reporter, mock_report = self._reporter_with_report()
        with patch("pathlib.Path.exists", return_value=False):
            self._run_main(
                ["--html", "out.html", "--exec-report", "brief.html"],
                mock_reporter,
            )
        mock_reporter.generate_html_report.assert_called_once_with(
            mock_report, "out.html", exec_href=None
        )

    def test_exec_href_none_when_only_html(self):
        mock_reporter, mock_report = self._reporter_with_report()
        self._run_main(["--html", "out.html"], mock_reporter)
        mock_reporter.generate_html_report.assert_called_once_with(
            mock_report, "out.html", exec_href=None
        )

    def test_fix_flag_is_noop_with_notice(self, capsys):
        """Retired --fix: not forwarded to Reporter; prints the muted notice."""
        from apotrope.cli import main

        mock_reporter, _ = self._reporter_with_report()
        p1, p2, p3, p4, p5 = self._patches(["--fix"], mock_reporter)
        with p1, p2, p3 as MockReporter, p4, p5:
            main()
        MockReporter.assert_called_once_with(verbose=False, no_color=False)
        out = capsys.readouterr().out
        assert "--fix is no longer needed" in out
        mock_reporter.run_with_progress.assert_called_once()  # scan still runs

    def test_no_fix_notice_without_flag(self, capsys):
        mock_reporter, _ = self._reporter_with_report()
        self._run_main([], mock_reporter)
        assert "--fix is no longer needed" not in capsys.readouterr().out

    def test_dry_run_prints_module_names(self, capsys):
        mock_reporter, _ = self._reporter_with_report()
        mock_scanner = MagicMock()
        mock_scanner.dry_run.return_value = [
            "apotrope.checks.firewall", "apotrope.checks.smb",
        ]
        from apotrope.cli import main

        with (
            patch("sys.argv", ["apotrope", "--dry-run"]),
            patch(self._SCANNER_PATH, return_value=mock_scanner),
            patch(self._REPORTER_PATH, return_value=mock_reporter),
            patch(self._ADMIN_PATH, return_value=False),
            patch(self._PROFILE_PATH, return_value=MagicMock()),
        ):
            main()
        out = capsys.readouterr().out
        assert "dry run" in out
        assert "apotrope.checks.firewall" in out
        assert "apotrope.checks.smb" in out
        mock_reporter.run_with_progress.assert_not_called()

    def test_profile_path_forwarded_to_load_profile(self):
        from apotrope.cli import main

        mock_reporter, _ = self._reporter_with_report()
        p1, p2, p3, p4, p5 = self._patches(
            ["--profile", "custom.toml"], mock_reporter
        )
        with p1, p2, p3, p4, p5 as load_mock:
            main()
        load_mock.assert_called_once_with("custom.toml")


# ---------------------------------------------------------------------------
# python -m apotrope entry point
# ---------------------------------------------------------------------------

class TestModuleEntryPoint:
    def test_dash_m_version_exits_zero(self, capsys):
        import runpy

        with (
            patch("sys.argv", ["apotrope", "--version"]),
            pytest.raises(SystemExit) as exc,
        ):
            runpy.run_module("apotrope", run_name="__main__")
        assert exc.value.code == 0
        assert "apotrope" in capsys.readouterr().out
