"""
Report manager for handling test results and generating reports.
"""

import os
from typing import Optional

from ..utils.logger import get_logger
from .base import TestResult, TestSummary, TestStatus
from .formatters import (
    ReportFormatter,
    JSONFormatter,
    MarkdownFormatter,
    GithubActionsFormatter,
    ConsoleFormatter
)

logger = get_logger(__name__)

class ReportManager:
    """Manager for handling test results and generating reports."""

    def __init__(self, debug_mode=False, test_type=None):
        """Initialize the report manager.

        Args:
            debug_mode: Whether to show detailed debug information
        """
        self.results = []
        self.debug_mode = debug_mode
        self.test_type = test_type
        self.formatters = {
            "json": JSONFormatter(debug_mode=debug_mode),
            "markdown": MarkdownFormatter(debug_mode=debug_mode),
            "github": GithubActionsFormatter(debug_mode=debug_mode),
            "console": ConsoleFormatter(debug_mode=debug_mode)
        }

    def add_result(self, result: TestResult) -> None:
        """Add a test result.

        Args:
            result: Test result to add
        """
        self.results.append(result)
        logger.debug(f"Added test result: {result.name} - {result.status.value}")

    def add_pytest_result(self, nodeid: str, status: str, message: str = "",
                         duration: float = 0.0) -> None:
        """Add a test result from pytest.

        Args:
            nodeid: pytest node ID
            status: Test status string
            message: Test message or failure reason
            duration: Test duration in seconds
        """

        module_name = nodeid.split("::")[0].split("/")[-1].replace(".py", "")
        module_name = module_name.replace("test_", "").capitalize()


        class_name = ""
        if "::" in nodeid:
            parts = nodeid.split("::")
            if len(parts) > 1 and parts[1] != "test_":
                class_name = parts[1].replace("Test", "")

        test_name = nodeid.split("::")[-1]
        test_name = test_name.replace("test_", "").replace("_", " ").capitalize()

        display_name = f"{module_name}: {test_name}"

        try:
            test_status = TestStatus(status.upper())
        except ValueError:
            if status.lower() == "passed":
                test_status = TestStatus.PASS
            elif status.lower() == "failed":
                test_status = TestStatus.FAIL
            elif status.lower() == "skipped":
                test_status = TestStatus.SKIPPED
            elif "error" in status.lower():
                test_status = TestStatus.ERROR
            elif "warn" in status.lower():
                test_status = TestStatus.WARNING
            else:
                test_status = TestStatus.ERROR

        result = TestResult(
            test_id=nodeid,
            name=display_name,
            status=test_status,
            message=message,
            duration=duration,
            module=module_name
        )
        self.add_result(result)

        status_colors = {
            TestStatus.PASS: "\033[92m",     # Green
            TestStatus.FAIL: "\033[91m",     # Red
            TestStatus.WARNING: "\033[93m",  # Yellow
            TestStatus.SKIPPED: "\033[94m",  # Blue
            TestStatus.ERROR: "\033[91m",    # Red
        }

        color = status_colors.get(test_status, "")
        reset = "\033[0m"

        logger.info(f"{color}{test_status.value}{reset} - {display_name}")

        if self.debug_mode and message and test_status != TestStatus.PASS:
            for line in message.split("\n"):
                logger.debug(f"  {line}")

    def get_summary(self) -> TestSummary:
        """Get a summary of test results.

        Returns:
            Test summary
        """
        return TestSummary(self.results, test_type=self.test_type)

    def generate_report(self, format_type: str = "console") -> str:
        """Generate a report in the specified format.

        Args:
            format_type: Report format type

        Returns:
            Formatted report as a string

        Raises:
            ValueError: If the format type is not supported
        """
        if format_type not in self.formatters:
            raise ValueError(f"Unsupported report format: {format_type}")

        summary = self.get_summary()
        return self.formatters[format_type].format_report(summary)

    def save_report(self, filename: str, format_type: Optional[str] = None) -> None:
        """Save a report to a file.

        Args:
            filename: Path to the output file
            format_type: Report format type (defaults to format based on file extension)

        Raises:
            ValueError: If the format type cannot be determined
        """

        if not format_type:
            ext = os.path.splitext(filename)[1].lower()
            if ext == '.json':
                format_type = 'json'
            elif ext == '.md':
                format_type = 'markdown'
            elif ext == '.github':
                format_type = 'github'
            else:
                format_type = 'console'

        if format_type == 'text':
            console_formatter = ConsoleFormatter(debug_mode=self.debug_mode, use_colors=False)
            report = console_formatter.format_report(self.get_summary())
        elif format_type == 'console' and os.path.exists(filename):
            console_formatter = ConsoleFormatter(debug_mode=self.debug_mode, use_colors=False)
            report = console_formatter.format_report(self.get_summary())
        else:
            report = self.generate_report(format_type)

        try:
            directory = os.path.dirname(filename)
            if directory and not os.path.exists(directory):
                os.makedirs(directory)

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)

            logger.info(f"Report saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving report to {filename}: {e}")
            raise

    def print_report(self) -> None:
        """Print a report to the console."""
        print(self.generate_report("console"))

    def clear(self) -> None:
        """Clear all test results."""
        self.results = []
