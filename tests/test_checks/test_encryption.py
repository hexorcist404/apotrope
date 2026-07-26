"""Tests for apotrope.checks.encryption."""

from __future__ import annotations

from unittest.mock import patch


from apotrope.checks import encryption
from apotrope.exceptions import ApotropeError
from apotrope.models import Status, Severity


# ---------------------------------------------------------------------------
# Shared mock data
# ---------------------------------------------------------------------------

def _vol(mount="C:", vol_type="OperatingSystem", status="FullyEncrypted",
         protection=1, method="XtsAes256", pct=100) -> dict:
    return {
        "MountPoint": mount,
        "VolumeType": vol_type,
        "VolumeStatus": status,
        "ProtectionStatus": protection,
        "EncryptionMethod": method,
        "EncryptionPercentage": pct,
    }


_OS_ENCRYPTED   = _vol("C:", "OperatingSystem", "FullyEncrypted",   protection=1, pct=100)
_OS_UNENCRYPTED = _vol("C:", "OperatingSystem", "FullyDecrypted",   protection=0, pct=0)
_DATA_ENCRYPTED = _vol("D:", "FixedDisk",        "FullyEncrypted",   protection=1, pct=100)
_DATA_PLAIN     = _vol("D:", "FixedDisk",        "FullyDecrypted",   protection=0, pct=0)
_OS_IN_PROGRESS = _vol("C:", "OperatingSystem", "EncryptionInProgress", protection=0, pct=45)


# ---------------------------------------------------------------------------
# run() — empty / unavailable
# ---------------------------------------------------------------------------

class TestEncryptionRunEmpty:
    def test_empty_list_returns_warn(self):
        with patch("apotrope.checks.encryption.run_powershell_json", return_value=[]):
            results = encryption.run()
        assert len(results) == 1
        assert results[0].status == Status.WARN
        assert results[0].severity == Severity.HIGH
        assert results[0].remediation != ""

    def test_ps_error_returns_error_result(self):
        with patch("apotrope.checks.encryption.run_powershell_json",
                   side_effect=ApotropeError("access denied")):
            results = encryption.run()
        assert len(results) == 1
        assert results[0].status == Status.ERROR

    def test_error_result_has_admin_remediation(self):
        with patch("apotrope.checks.encryption.run_powershell_json",
                   side_effect=ApotropeError("access denied")):
            results = encryption.run()
        assert "Administrator" in results[0].remediation


# ---------------------------------------------------------------------------
# run() — single OS drive
# ---------------------------------------------------------------------------

class TestEncryptionRunOsDrive:
    def test_encrypted_os_drive_returns_pass(self):
        with patch("apotrope.checks.encryption.run_powershell_json",
                   return_value=[_OS_ENCRYPTED]):
            results = encryption.run()
        assert len(results) == 1
        assert results[0].status == Status.PASS
        assert results[0].severity == Severity.HIGH

    def test_unencrypted_os_drive_returns_high_fail(self):
        with patch("apotrope.checks.encryption.run_powershell_json",
                   return_value=[_OS_UNENCRYPTED]):
            results = encryption.run()
        assert results[0].status == Status.FAIL
        assert results[0].severity == Severity.HIGH
        assert results[0].remediation != ""
        assert "Enable-BitLocker" in results[0].command

    def test_unencrypted_os_drive_remediation_includes_mount_point(self):
        with patch("apotrope.checks.encryption.run_powershell_json",
                   return_value=[_OS_UNENCRYPTED]):
            results = encryption.run()
        assert "C:" in results[0].remediation

    def test_encryption_in_progress_treated_as_unprotected(self):
        """ProtectionStatus=0 while encrypting → still FAIL until protection is On."""
        with patch("apotrope.checks.encryption.run_powershell_json",
                   return_value=[_OS_IN_PROGRESS]):
            results = encryption.run()
        assert results[0].status == Status.FAIL
        assert "45%" in results[0].details

    def test_pass_details_include_encryption_method(self):
        with patch("apotrope.checks.encryption.run_powershell_json",
                   return_value=[_OS_ENCRYPTED]):
            results = encryption.run()
        assert "XtsAes256" in results[0].details


# ---------------------------------------------------------------------------
# run() — data drives
# ---------------------------------------------------------------------------

class TestEncryptionRunDataDrives:
    def test_encrypted_data_drive_returns_pass_medium(self):
        with patch("apotrope.checks.encryption.run_powershell_json",
                   return_value=[_DATA_ENCRYPTED]):
            results = encryption.run()
        assert results[0].status == Status.PASS
        assert results[0].severity == Severity.MEDIUM

    def test_unencrypted_data_drive_returns_medium_fail(self):
        with patch("apotrope.checks.encryption.run_powershell_json",
                   return_value=[_DATA_PLAIN]):
            results = encryption.run()
        assert results[0].status == Status.FAIL
        assert results[0].severity == Severity.MEDIUM

    def test_check_name_includes_drive_letter(self):
        with patch("apotrope.checks.encryption.run_powershell_json",
                   return_value=[_DATA_PLAIN]):
            results = encryption.run()
        assert "D:" in results[0].check_name


# ---------------------------------------------------------------------------
# run() — multiple drives
# ---------------------------------------------------------------------------

class TestEncryptionRunMultipleDrives:
    def test_mixed_drives_returns_one_result_per_drive(self):
        with patch("apotrope.checks.encryption.run_powershell_json",
                   return_value=[_OS_ENCRYPTED, _DATA_PLAIN]):
            results = encryption.run()
        assert len(results) == 2

    def test_os_pass_and_data_fail(self):
        with patch("apotrope.checks.encryption.run_powershell_json",
                   return_value=[_OS_ENCRYPTED, _DATA_PLAIN]):
            results = encryption.run()
        c_result = next(r for r in results if "C:" in r.check_name)
        d_result = next(r for r in results if "D:" in r.check_name)
        assert c_result.status == Status.PASS
        assert d_result.status == Status.FAIL

    def test_all_encrypted_all_pass(self):
        with patch("apotrope.checks.encryption.run_powershell_json",
                   return_value=[_OS_ENCRYPTED, _DATA_ENCRYPTED]):
            results = encryption.run()
        assert all(r.status == Status.PASS for r in results)

    def test_all_unencrypted_all_fail(self):
        with patch("apotrope.checks.encryption.run_powershell_json",
                   return_value=[_OS_UNENCRYPTED, _DATA_PLAIN]):
            results = encryption.run()
        assert all(r.status == Status.FAIL for r in results)

    def test_single_dict_response_treated_as_one_volume(self):
        """PS returns bare dict when only one volume exists."""
        with patch("apotrope.checks.encryption.run_powershell_json",
                   return_value=_OS_ENCRYPTED):
            results = encryption.run()
        assert len(results) == 1

    def test_null_fields_do_not_crash(self):
        vol = {"MountPoint": "E:", "VolumeType": None, "VolumeStatus": None,
               "ProtectionStatus": None, "EncryptionMethod": None,
               "EncryptionPercentage": None}
        with patch("apotrope.checks.encryption.run_powershell_json", return_value=[vol]):
            results = encryption.run()
        assert len(results) == 1
        assert results[0].status == Status.FAIL  # ProtectionStatus None → 0 → Off


class TestEncryptionFixes:
    def _run(self, vol):
        with patch("apotrope.checks.encryption.run_powershell_json", return_value=[vol]):
            return encryption.run()

    def test_protected_but_partial_is_warn_not_pass(self):
        # Protection On but only 55% encrypted → not yet fully protected → WARN.
        vol = _vol("C:", "OperatingSystem", "EncryptionInProgress", protection=1, pct=55)
        r = self._run(vol)[0]
        assert r.status == Status.WARN
        assert "55%" in r.details

    def test_integer_enums_mapped_in_details(self):
        # PS 5.1 serialises the enums as integers; they must render as names.
        vol = {"MountPoint": "C:", "VolumeType": 0, "VolumeStatus": 1,
               "ProtectionStatus": 1, "EncryptionMethod": "XtsAes256",
               "EncryptionPercentage": 100}
        r = self._run(vol)[0]
        assert r.status == Status.PASS
        assert "OperatingSystem" in r.details
        assert "FullyEncrypted" in r.details

    def test_ps7_string_protection_status_handled(self):
        # PS 7 may serialise ProtectionStatus/percentage as strings; int() would crash.
        vol = {"MountPoint": "C:", "VolumeType": "OperatingSystem",
               "VolumeStatus": "FullyEncrypted", "ProtectionStatus": "On",
               "EncryptionMethod": "XtsAes256", "EncryptionPercentage": "100"}
        r = self._run(vol)[0]
        assert r.status == Status.PASS

    def test_remediation_hands_the_operator_the_recovery_key(self):
        # Enabling BitLocker without showing the recovery password leaves the
        # operator one firmware update away from an unopenable disk: the cmdlets
        # print the protector types, not the 48-digit key, and the recovery
        # prompt cannot read it back.
        vol = _vol("D:", "FixedDataVolume", "FullyDecrypted", protection=0, pct=0)
        r = self._run(vol)[0]
        assert "-RecoveryPasswordProtector" in r.command
        active = "\n".join(
            ln for ln in r.command.splitlines() if not ln.lstrip().startswith("#")
        )
        assert "RecoveryPassword" in active.replace("-RecoveryPasswordProtector", "")
        assert "SAVE THIS BEFORE YOU REBOOT" in r.command

    def test_os_drive_remediation_hands_over_the_key_too(self):
        vol = _vol("C:", "OperatingSystem", "FullyDecrypted", protection=0, pct=0)
        r = self._run(vol)[0]
        active = "\n".join(
            ln for ln in r.command.splitlines() if not ln.lstrip().startswith("#")
        )
        assert "Format-List KeyProtectorId, RecoveryPassword" in active
