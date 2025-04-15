"""
Report formatters for different output formats.
"""

import json
from datetime import datetime

from ..config import get_logger
from .base import TestSummary, TestStatus, get_status_color, COLOR_RESET

logger = get_logger(__name__)


def _process_error_message(message: str, debug_mode: bool = False) -> str:
    """Processes an error message for proper display.

    Args:
        message: Error message to process
        debug_mode: If True, displays the full message; if False, simplifies it

    Returns:
        Processed message
    """
    if not message:
        return ""

    if debug_mode:
        return message

    if "\n" in message and any(line.strip().startswith("- ") for line in message.split("\n")):
        error_lines = [line for line in message.split("\n")
                      if line.strip() and line.strip().startswith("- ")]
        if error_lines:
            return "\n".join(error_lines)

    if "AssertionError:" in message:
        parts = message.split("AssertionError:", 1)
        if len(parts) > 1:
            error_part = parts[1].strip()
            if "\n" in error_part:
                error_lines = []
                for line in error_part.split("\n"):
                    line = line.strip()
                    if line and not line.startswith(">") and not line.startswith("E "):
                        error_lines.append(f"- {line}")
                if error_lines:
                    return "\n".join(error_lines)
            return error_part

    if "\n" in message:
        potential_lines = [line.strip() for line in message.split("\n")
                          if line.strip() and not line.startswith(">") and not line.startswith("E ")]

        if potential_lines:
            if len(potential_lines) == 1:
                return potential_lines[0]
            else:
                return "\n".join(f"- {line}" for line in potential_lines)

    return message.split("\n")[0] if "\n" in message else message


class ReportFormatter:
    """Base class for report formatters."""

    def format_report(self, summary: TestSummary) -> str:
        """Format test summary into report.

        Args:
            summary: Test summary to format

        Returns:
            Formatted report as string
        """
        raise NotImplementedError("Subclasses must implement format_report")


class JSONFormatter(ReportFormatter):
    """JSON report formatter."""

    def __init__(self, debug_mode=False):
        """Inicializar el formateador.

        Args:
            debug_mode: Si es True, incluye información detallada de errores
        """
        self.debug_mode = debug_mode

    def format_report(self, summary: TestSummary) -> str:
        """Format test summary as JSON.

        Args:
            summary: Test summary to format

        Returns:
            JSON string representation of the report
        """
        summary_data = summary.to_dict()

        processed_results = []
        for result in summary.results:
            result_dict = result.to_dict()

            if result.message:
                result_dict['message'] = _process_error_message(result.message, self.debug_mode)

            processed_results.append(result_dict)

        report_data = {
            "summary": summary_data,
            "results": processed_results,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        return json.dumps(report_data, indent=2)


class MarkdownFormatter(ReportFormatter):
    """Markdown report formatter."""

    def __init__(self, debug_mode=False):
        """Inicializar el formateador.

        Args:
            debug_mode: Si es True, muestra información detallada de los errores
        """
        self.debug_mode = debug_mode

    def _get_status_emoji(self, status: TestStatus) -> str:
        """Returns the appropriate emoji for a test state.

        Args:
            status: Test state

        Returns:
            Emoji corresponding to the state
        """
        status_emojis = {
            TestStatus.PASS: ":green_circle:",
            TestStatus.FAIL: ":red_circle:",
            TestStatus.WARNING: ":yellow_circle:",
            TestStatus.SKIPPED: ":blue_circle:",
            TestStatus.ERROR: ":red_circle:"
        }
        return status_emojis.get(status, "")

    def format_report(self, summary: TestSummary) -> str:
        """Format test summary as Markdown.

        Args:
            summary: Test summary to format

        Returns:
            Markdown string representation of the report
        """
        status_emoji = self._get_status_emoji(summary.status)

        markdown = f"# Wazuh VM Test Results\n\n"
        markdown += f"## Summary\n\n"
        markdown += f"**Status**: {summary.status.value} {status_emoji}\n\n"
        markdown += f"| Metric | Count |\n"
        markdown += f"|--------|-------|\n"
        markdown += f"| Total Tests | {summary.total} |\n"
        markdown += f"| Passed | {summary.passed} |\n"
        markdown += f"| Failed | {summary.failed}|\n"
        markdown += f"| Warnings | {summary.warnings} |\n"
        markdown += f"| Skipped | {summary.skipped} |\n"

        # Group by test
        tests_by_module = {}
        for result in summary.results:
            module = result.module or "Other"
            if module not in tests_by_module:
                tests_by_module[module] = []
            tests_by_module[module].append(result)

        # Test failed with details
        if summary.failed > 0:
            markdown += f"\n## Failed Tests {self._get_status_emoji(TestStatus.FAIL)}\n\n"

            for module, tests in tests_by_module.items():
                failed_tests = [t for t in tests if t.status == TestStatus.FAIL]
                if not failed_tests:
                    continue

                markdown += f"### {module}\n\n"
                for test in failed_tests:
                    markdown += f"**{test.name}** {self._get_status_emoji(test.status)}\n\n"
                    if test.message:
                        processed_message = _process_error_message(test.message, self.debug_mode)

                        if self.debug_mode:
                            markdown += f"```\n{processed_message}\n```\n\n"
                        else:
                            if "\n" in processed_message and any(line.startswith("- ") for line in processed_message.split("\n")):
                                markdown += "Errors found:\n\n"
                                for line in processed_message.split("\n"):
                                    markdown += f"{line}\n"
                                markdown += "\n"
                            else:
                                markdown += f"Error: `{processed_message}`\n\n"

        # Success test
        if summary.passed > 0:
            markdown += f"\n## Passed Tests \n\n"

            for module, tests in sorted(tests_by_module.items()):
                passed_tests = [t for t in tests if t.status == TestStatus.PASS]
                if not passed_tests:
                    continue

                markdown += f"### {module}\n\n"
                for test in passed_tests:
                    markdown += f"- {test.name} {self._get_status_emoji(test.status)}\n"
                markdown += "\n"

        # Skipped test
        if summary.skipped > 0:
            markdown += f"\n## Skipped Tests {self._get_status_emoji(TestStatus.SKIPPED)}\n\n"

            for module, tests in sorted(tests_by_module.items()):
                skipped_tests = [t for t in tests if t.status == TestStatus.SKIPPED]
                if not skipped_tests:
                    continue

                markdown += f"### {module}\n\n"
                for test in skipped_tests:
                    markdown += f"**{test.name}** {self._get_status_emoji(test.status)}\n\n"
                    if test.message:
                        reason = _process_error_message(test.message, False).split("\n")[0]
                        markdown += f"Reason: `{reason}`\n\n"

        # Warning test if any
        warning_tests = [t for t in summary.results if t.status == TestStatus.WARNING]
        if warning_tests:
            markdown += f"\n## Warning Tests {self._get_status_emoji(TestStatus.WARNING)}\n\n"

            tests_by_module = {}
            for result in warning_tests:
                module = result.module or "Other"
                if module not in tests_by_module:
                    tests_by_module[module] = []
                tests_by_module[module].append(result)

            for module, tests in sorted(tests_by_module.items()):
                markdown += f"### {module}\n\n"
                for test in tests:
                    markdown += f"**{test.name}** {self._get_status_emoji(test.status)}\n\n"
                    if test.message:
                        reason = _process_error_message(test.message, self.debug_mode)
                        if self.debug_mode:
                            markdown += f"```\n{reason}\n```\n\n"
                        else:
                            markdown += f"Warning: `{reason}`\n\n"

        return markdown

class GithubActionsFormatter(ReportFormatter):
    """GitHub Actions compatible formatter."""

    def __init__(self, debug_mode=False):
        """Initialize the formatter.

        Args:
            debug_mode: If True, displays detailed error information.
        """
        self.debug_mode = debug_mode

    def format_report(self, summary: TestSummary) -> str:
        """Format test summary for GitHub Actions.

        Args:
            summary: Test summary to format

        Returns:
            GitHub Actions compatible output format
        """
        # MarkDown format
        markdown = MarkdownFormatter(debug_mode=self.debug_mode).format_report(summary)

        # GitHub Actions format
        short_summary = f"Tests Summary: {summary.status.value} - Total: {summary.total}, Passed: {summary.passed}, Failed: {summary.failed}, Skipped: {summary.skipped}"

        github_data = (
            f"test_status={summary.status.value}\n"
            f"total_tests={summary.total}\n"
            f"passed_tests={summary.passed}\n"
            f"failed_tests={summary.failed}\n"
            f"warning_tests={summary.warnings}\n"
            f"skipped_tests={summary.skipped}\n"
            f"short_summary={short_summary}\n"
            f"summary<<EOF\n{markdown}\nEOF\n"
        )

        return github_data


class ConsoleFormatter(ReportFormatter):
    """Console (terminal) report formatter with ANSI colors."""

    # Console format - colores adicionales que no están en STATUS_COLORS
    COLORS = {
        "RESET": COLOR_RESET,
        "BOLD": "\033[1m",
        "MAGENTA": "\033[95m",
        "CYAN": "\033[96m",
        "WHITE": "\033[97m",
        "BG_RED": "\033[41m",
        "BG_GREEN": "\033[42m",
        "BG_YELLOW": "\033[43m",
        "BG_BLUE": "\033[44m",
    }

    def __init__(self, debug_mode=False, use_colors=True):
        """Initialize the formatter.

        Args:
            debug_mode: If True, display detailed error information
            use_colors: If True, use ANSI colors in the output
        """
        self.debug_mode = debug_mode
        self.use_colors = use_colors

    def _get_color(self, color_name):
        """Returns the color code or an empty string if no colors are used.

        Args:
            color_name: Color name in self.COLORS

        Returns:
            ANSI code or empty string
        """
        if not self.use_colors:
            return ""
        return self.COLORS.get(color_name, "")

    def format_report(self, summary: TestSummary) -> str:
        """Format test summary for console output with optional colors.

        Args:
            summary: Test summary to format

        Returns:
            Formatted console output
        """
        output = []

        output.append("\n" + "=" * 80)
        output.append(f"{self._get_color('BOLD')}Wazuh VM Test Summary{self._get_color('RESET')}")
        output.append("=" * 80)

        # Print status by color
        status_color = get_status_color(summary.status, self.use_colors)
        output.append(f"\nOverall Status: {status_color}{self._get_color('BOLD')}{summary.status.value}{self._get_color('RESET')}")

        # Print statistics
        output.append(f"\nTotal Tests: {summary.total}")
        output.append(f"Passed: {get_status_color(TestStatus.PASS, self.use_colors)}{summary.passed}{self._get_color('RESET')}")
        output.append(f"Failed: {get_status_color(TestStatus.FAIL, self.use_colors)}{summary.failed}{self._get_color('RESET')}")
        output.append(f"Warnings: {get_status_color(TestStatus.WARNING, self.use_colors)}{summary.warnings}{self._get_color('RESET')}")
        output.append(f"Errors: {get_status_color(TestStatus.ERROR, self.use_colors)}{summary.errors}{self._get_color('RESET')}")
        output.append(f"Skipped: {get_status_color(TestStatus.SKIPPED, self.use_colors)}{summary.skipped}{self._get_color('RESET')}")

        # Group tests by module
        tests_by_module = {}
        for result in summary.results:
            module = result.module or "Other"
            if module not in tests_by_module:
                tests_by_module[module] = []
            tests_by_module[module].append(result)

        # First show failed test
        if summary.failed > 0 or summary.errors > 0:
            output.append("\n" + "-" * 80)
            output.append(f"{self._get_color('BOLD')}Failed Tests{self._get_color('RESET')}")
            output.append("-" * 80)

            for module, tests in tests_by_module.items():
                failed_tests = [t for t in tests if t.status in [TestStatus.FAIL, TestStatus.ERROR]]
                if not failed_tests:
                    continue

                output.append(f"\n{self._get_color('BOLD')}{module} Module:{self._get_color('RESET')}")
                for test in failed_tests:
                    status_color = get_status_color(test.status, self.use_colors)
                    output.append(f"  {status_color}✘ {test.name}{self._get_color('RESET')}")

                    if test.message:
                        processed_message = _process_error_message(test.message, self.debug_mode)

                        if self.debug_mode:
                            output.append(f"    {self._get_color('CYAN')}Error details:{self._get_color('RESET')}")
                            for line in processed_message.split("\n"):
                                output.append(f"      {line}")
                        else:
                            if "\n" in processed_message:
                                output.append(f"    {self._get_color('CYAN')}Errors found:{self._get_color('RESET')}")
                                for line in processed_message.split("\n"):
                                    if not line.startswith("- ") and line.strip():
                                        line = f"- {line}"
                                    output.append(f"      {line}")
                            else:
                                message = processed_message[:150] + "..." if len(processed_message) > 150 else processed_message
                                output.append(f"    {self._get_color('CYAN')}→ {message}{self._get_color('RESET')}")

        # Show success tests
        if summary.passed > 0:
            output.append("\n" + "-" * 80)
            output.append(f"{self._get_color('BOLD')}Passed Tests{self._get_color('RESET')}")
            output.append("-" * 80)

            for module, tests in tests_by_module.items():
                passed_tests = [t for t in tests if t.status == TestStatus.PASS]
                if not passed_tests:
                    continue

                output.append(f"\n{self._get_color('BOLD')}{module} Module:{self._get_color('RESET')}")
                for test in passed_tests:
                    status_color = get_status_color(TestStatus.PASS, self.use_colors)
                    output.append(f"  {status_color}✓ {test.name}{self._get_color('RESET')}")

        # Show warnings and skipped tests
        if summary.warnings > 0 or summary.skipped > 0:
            output.append("\n" + "-" * 80)
            output.append(f"{self._get_color('BOLD')}Warnings & Skipped{self._get_color('RESET')}")
            output.append("-" * 80)

            for module, tests in tests_by_module.items():
                other_tests = [t for t in tests if t.status in [TestStatus.WARNING, TestStatus.SKIPPED]]
                if not other_tests:
                    continue

                output.append(f"\n{self._get_color('BOLD')}{module} Module:{self._get_color('RESET')}")
                for test in other_tests:
                    status_color = get_status_color(test.status, self.use_colors)
                    if test.status == TestStatus.WARNING:
                        status_symbol = f"{status_color}⚠"
                    else:
                        status_symbol = f"{status_color}○"
                    output.append(f"  {status_symbol} {test.name}{self._get_color('RESET')}")

                    if test.message:
                        processed_message = _process_error_message(test.message, self.debug_mode)

                        if self.debug_mode and test.status == TestStatus.WARNING:
                            output.append(f"    {self._get_color('CYAN')}Warning details:{self._get_color('RESET')}")
                            for line in processed_message.split("\n"):
                                output.append(f"      {line}")
                        else:
                            if "\n" in processed_message:
                                for line in processed_message.split("\n"):
                                    output.append(f"    {self._get_color('CYAN')}→ {line[:150]}{self._get_color('RESET')}")
                            else:
                                output.append(f"    {self._get_color('CYAN')}→ {processed_message[:150]}{self._get_color('RESET')}")

        return "\n".join(output)
