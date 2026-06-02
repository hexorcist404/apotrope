"""Unit tests for apotrope.scoring."""

from __future__ import annotations

import pytest

from apotrope.models import CheckResult, Severity, Status
from apotrope.scoring import (
    calculate_category_scores,
    calculate_score,
    score_grade,
    score_label,
)


def _result(status: Status, severity: Severity, category: str = "Test") -> CheckResult:
    return CheckResult(
        category=category,
        check_name="test check",
        status=status,
        severity=severity,
        description="",
        details="",
    )


# ---------------------------------------------------------------------------
# calculate_score
# ---------------------------------------------------------------------------

class TestCalculateScore:
    def test_empty_results_returns_100(self):
        assert calculate_score([]) == 100

    def test_all_pass_returns_100(self):
        results = [_result(Status.PASS, Severity.HIGH) for _ in range(5)]
        assert calculate_score(results) == 100

    # --- FAIL deductions ---

    def test_critical_fail_deducts_15(self):
        assert calculate_score([_result(Status.FAIL, Severity.CRITICAL)]) == 85

    def test_high_fail_deducts_10(self):
        assert calculate_score([_result(Status.FAIL, Severity.HIGH)]) == 90

    def test_medium_fail_deducts_5(self):
        assert calculate_score([_result(Status.FAIL, Severity.MEDIUM)]) == 95

    def test_low_fail_deducts_2(self):
        assert calculate_score([_result(Status.FAIL, Severity.LOW)]) == 98

    def test_info_fail_no_deduction(self):
        assert calculate_score([_result(Status.FAIL, Severity.INFO)]) == 100

    # --- WARN deductions (floor(FAIL/2)) ---

    def test_critical_warn_deducts_7(self):
        assert calculate_score([_result(Status.WARN, Severity.CRITICAL)]) == 93

    def test_high_warn_deducts_5(self):
        assert calculate_score([_result(Status.WARN, Severity.HIGH)]) == 95

    def test_medium_warn_deducts_2(self):
        assert calculate_score([_result(Status.WARN, Severity.MEDIUM)]) == 98

    def test_low_warn_deducts_1(self):
        assert calculate_score([_result(Status.WARN, Severity.LOW)]) == 99

    def test_info_warn_no_deduction(self):
        assert calculate_score([_result(Status.WARN, Severity.INFO)]) == 100

    # --- Non-penalised statuses ---

    def test_info_status_no_deduction(self):
        assert calculate_score([_result(Status.INFO, Severity.CRITICAL)]) == 100

    def test_error_status_no_deduction(self):
        assert calculate_score([_result(Status.ERROR, Severity.HIGH)]) == 100

    def test_pass_status_no_deduction(self):
        assert calculate_score([_result(Status.PASS, Severity.CRITICAL)]) == 100

    # --- Clamping ---

    def test_score_clamps_to_zero(self):
        # 7 × CRITICAL FAIL = −105 → clamp to 0
        results = [_result(Status.FAIL, Severity.CRITICAL) for _ in range(7)]
        assert calculate_score(results) == 0

    def test_score_never_exceeds_100(self):
        assert calculate_score([_result(Status.PASS, Severity.INFO)]) <= 100

    # --- Mixed combinations ---

    def test_mixed_fail_and_warn(self):
        # CRITICAL FAIL (−15) + HIGH WARN (−5) = −20 → 80
        results = [
            _result(Status.FAIL, Severity.CRITICAL),
            _result(Status.WARN, Severity.HIGH),
        ]
        assert calculate_score(results) == 80

    def test_mixed_with_pass_unchanged(self):
        # FAIL HIGH (−10) + PASS + INFO = 90
        results = [
            _result(Status.FAIL, Severity.HIGH),
            _result(Status.PASS, Severity.CRITICAL),
            _result(Status.INFO, Severity.CRITICAL),
        ]
        assert calculate_score(results) == 90

    def test_multiple_medium_fails(self):
        # 4 × MEDIUM FAIL = −20 → 80
        results = [_result(Status.FAIL, Severity.MEDIUM) for _ in range(4)]
        assert calculate_score(results) == 80

    def test_all_critical_fail(self):
        results = [_result(Status.FAIL, Severity.CRITICAL) for _ in range(10)]
        assert calculate_score(results) == 0

    def test_accumulates_across_severities(self):
        # CRITICAL FAIL(−15) + HIGH FAIL(−10) + MEDIUM FAIL(−5) + LOW FAIL(−2) = −32 → 68
        results = [
            _result(Status.FAIL, Severity.CRITICAL),
            _result(Status.FAIL, Severity.HIGH),
            _result(Status.FAIL, Severity.MEDIUM),
            _result(Status.FAIL, Severity.LOW),
        ]
        assert calculate_score(results) == 68


# ---------------------------------------------------------------------------
# calculate_category_scores
# ---------------------------------------------------------------------------

class TestCalculateCategoryScores:
    def test_empty_results_returns_empty_dict(self):
        assert calculate_category_scores([]) == {}

    def test_single_category_matches_overall(self):
        results = [_result(Status.FAIL, Severity.HIGH, category="Firewall")]
        scores = calculate_category_scores(results)
        assert scores == {"Firewall": 90}

    def test_categories_scored_independently(self):
        results = [
            _result(Status.FAIL, Severity.CRITICAL, category="Firewall"),
            _result(Status.PASS, Severity.HIGH,     category="Accounts"),
        ]
        scores = calculate_category_scores(results)
        assert scores["Firewall"] == 85   # −15
        assert scores["Accounts"] == 100  # no deduction

    def test_categories_do_not_bleed_into_each_other(self):
        # 7 CRITICAL FAILs in Firewall should not affect Accounts
        results = (
            [_result(Status.FAIL, Severity.CRITICAL, category="Firewall")] * 7
            + [_result(Status.PASS, Severity.CRITICAL, category="Accounts")]
        )
        scores = calculate_category_scores(results)
        assert scores["Firewall"] == 0
        assert scores["Accounts"] == 100

    def test_multiple_checks_same_category(self):
        results = [
            _result(Status.FAIL, Severity.HIGH,   category="Network"),
            _result(Status.WARN, Severity.MEDIUM, category="Network"),
        ]
        scores = calculate_category_scores(results)
        # HIGH FAIL(−10) + MEDIUM WARN(−2) = −12 → 88
        assert scores["Network"] == 88

    def test_returns_sorted_category_names(self):
        results = [
            _result(Status.PASS, Severity.LOW, category="Zebra"),
            _result(Status.PASS, Severity.LOW, category="Alpha"),
        ]
        scores = calculate_category_scores(results)
        assert list(scores.keys()) == ["Alpha", "Zebra"]


# ---------------------------------------------------------------------------
# score_grade
# ---------------------------------------------------------------------------

class TestScoreGrade:
    @pytest.mark.parametrize("score,letter,label", [
        (100, "A", "Excellent"),
        (90,  "A", "Excellent"),
        (89,  "B", "Good"),
        (80,  "B", "Good"),
        (79,  "C", "Fair"),
        (70,  "C", "Fair"),
        (69,  "D", "Poor"),
        (60,  "D", "Poor"),
        (59,  "F", "Critical"),
        (1,   "F", "Critical"),
        (0,   "F", "Critical"),
    ])
    def test_grades(self, score: int, letter: str, label: str):
        got_letter, got_label = score_grade(score)
        assert got_letter == letter
        assert got_label == label


# ---------------------------------------------------------------------------
# score_label
# ---------------------------------------------------------------------------

class TestScoreLabel:
    @pytest.mark.parametrize("score,expected", [
        (100, "Excellent"),
        (90,  "Excellent"),
        (89,  "Good"),
        (80,  "Good"),
        (79,  "Fair"),
        (70,  "Fair"),
        (69,  "Poor"),
        (60,  "Poor"),
        (59,  "Critical"),
        (0,   "Critical"),
    ])
    def test_labels(self, score: int, expected: str):
        assert score_label(score) == expected
