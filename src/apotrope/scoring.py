"""Risk scoring logic for Apotrope.

Calculates a 0–100 security score from a list of CheckResult objects.
Scoring model:
  - Start at 100
  - Deduct per FAIL/WARN check, weighted by severity
  - WARN deducts half the corresponding FAIL amount (integer floor)
  - Clamp final score to [0, 100]

Deduction table:
  Severity   FAIL   WARN
  CRITICAL    -15    -7
  HIGH        -10    -5
  MEDIUM       -5    -2
  LOW          -2    -1
  INFO          0     0

Grade thresholds:
  90-100 → A  Excellent
  80-89  → B  Good
  70-79  → C  Fair
  60-69  → D  Poor
   0-59  → F  Critical
"""

from __future__ import annotations

import logging
from collections import defaultdict

from apotrope.models import CheckResult, Severity, Status

log = logging.getLogger(__name__)

# Deduction points per (status, severity) combination.
# WARN = floor(FAIL / 2) for each severity level.
_DEDUCTIONS: dict[tuple[Status, Severity], int] = {
    (Status.FAIL, Severity.CRITICAL): 15,
    (Status.FAIL, Severity.HIGH):     10,
    (Status.FAIL, Severity.MEDIUM):    5,
    (Status.FAIL, Severity.LOW):       2,
    (Status.FAIL, Severity.INFO):      0,
    (Status.WARN, Severity.CRITICAL):  7,   # floor(15/2)
    (Status.WARN, Severity.HIGH):      5,   # floor(10/2)
    (Status.WARN, Severity.MEDIUM):    2,   # floor(5/2)
    (Status.WARN, Severity.LOW):       1,   # floor(2/2)
    (Status.WARN, Severity.INFO):      0,
}

# Letter grades
_GRADES: list[tuple[int, str, str]] = [
    (90, "A", "Excellent"),
    (80, "B", "Good"),
    (70, "C", "Fair"),
    (60, "D", "Poor"),
    (0,  "F", "Critical"),
]


def calculate_score(results: list[CheckResult]) -> int:
    """Calculate an overall security score from a list of check results.

    Args:
        results: All CheckResult objects from the scan.

    Returns:
        An integer score in the range [0, 100].
    """
    score = 100
    for result in results:
        deduction = _DEDUCTIONS.get((result.status, result.severity), 0)
        if deduction:
            log.debug(
                "  -%d for %s (%s / %s)",
                deduction,
                result.check_name,
                result.status,
                result.severity,
            )
        score -= deduction

    final = max(0, min(100, score))
    log.info("Final security score: %d", final)
    return final


def calculate_category_scores(results: list[CheckResult]) -> dict[str, int]:
    """Calculate a security score for each category independently.

    Each category starts at 100 and deductions are applied only from
    results belonging to that category.

    Args:
        results: All CheckResult objects from the scan.

    Returns:
        A dict mapping category name → integer score in [0, 100].
    """
    by_category: dict[str, list[CheckResult]] = defaultdict(list)
    for result in results:
        by_category[result.category].append(result)

    return {
        category: calculate_score(cat_results)
        for category, cat_results in sorted(by_category.items())
    }


def score_grade(score: int) -> tuple[str, str]:
    """Return the letter grade and label for a numeric score.

    Args:
        score: Integer score 0–100.

    Returns:
        Tuple of (letter, label), e.g. ("A", "Excellent") or ("F", "Critical").
    """
    for threshold, letter, label in _GRADES:
        if score >= threshold:
            return letter, label
    return "F", "Critical"


def score_label(score: int) -> str:
    """Return a human-readable label for a numeric score.

    Args:
        score: Integer score 0–100.

    Returns:
        One of: "Excellent", "Good", "Fair", "Poor", "Critical".
    """
    _, label = score_grade(score)
    return label
