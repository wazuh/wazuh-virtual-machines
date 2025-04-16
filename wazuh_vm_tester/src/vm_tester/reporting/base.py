"""
Base classes and utilities for test reporting.
"""

from enum import Enum
from typing import Dict, List, Any
from datetime import datetime

from ..utils.logger import get_logger

logger = get_logger(__name__)


class TestStatus(str, Enum):
    """Possible states for a test."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"

STATUS_COLORS = {
    TestStatus.PASS: "\033[92m",     # Green
    TestStatus.FAIL: "\033[91m",     # Red
    TestStatus.WARNING: "\033[93m",  # Yellow
    TestStatus.SKIPPED: "\033[94m",  # Blue
    TestStatus.ERROR: "\033[91m",    # Red
}

COLOR_RESET = "\033[0m"


def get_status_color(status: TestStatus, use_colors: bool = True) -> str:
    """Gets the ANSI color code for a test status.

    Args:
        status: Test status
        use_colors: If False, returns an empty string

    Returns:
        ANSI color code or empty string
    """
    if not use_colors:
        return ""
    return STATUS_COLORS.get(status, "")


class TestResult:
    """Class representing a single test result."""

    def __init__(
        self,
        test_id: str,
        name: str,
        status: TestStatus,
        message: str = "",
        duration: float = 0.0,
        module: str = "",
    ):
        """Initialize a test result.

        Args:
            test_id: Unique identifier for the test
            name: Display name of the test
            status: Test status (PASS, FAIL, etc.)
            message: Test message or failure reason
            duration: Test duration in seconds
            module: Test module name
        """
        self.id = test_id
        self.name = name
        self.status = status
        self.message = message
        self.duration = duration
        self.module = module
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary.

        Returns:
            Dictionary representation of the test result
        """
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "duration": self.duration,
            "module": self.module,
            "timestamp": self.timestamp,
        }


class TestSummary:
    """Class representing a summary of test results."""

    def __init__(self, results: List[TestResult]):
        """Initialize a test summary.

        Args:
            results: List of test results
        """
        self.results = results
        self.total = len(results)
        self.passed = sum(1 for r in results if r.status == TestStatus.PASS)
        self.failed = sum(1 for r in results if r.status == TestStatus.FAIL)
        self.warnings = sum(1 for r in results if r.status == TestStatus.WARNING)
        self.errors = sum(1 for r in results if r.status == TestStatus.ERROR)
        self.skipped = sum(1 for r in results if r.status == TestStatus.SKIPPED)

        # Determine overall status
        self.status = TestStatus.PASS
        if self.failed > 0 or self.errors > 0:
            self.status = TestStatus.FAIL
        elif self.warnings > 0:
            self.status = TestStatus.WARNING

        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to dictionary.

        Returns:
            Dictionary representation of the test summary
        """
        return {
            "status": self.status.value,
            "total": self.total,
            "pass": self.passed,
            "fail": self.failed,
            "warning": self.warnings,
            "error": self.errors,
            "skipped": self.skipped,
            "timestamp": self.timestamp,
        }
