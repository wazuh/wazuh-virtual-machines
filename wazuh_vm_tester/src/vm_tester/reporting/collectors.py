"""
Module to collect test results from pytest.
"""

from typing import List
from ..config import get_logger
from .base import TestResult, TestStatus, get_status_color, COLOR_RESET

logger = get_logger(__name__)

class ResultCollector:
    def __init__(self, log_level="INFO"):
        """Initializes the results collector.

        Args:
            log_level: Logging level to control the detail.
        """
        self.results = []
        self.log_level = log_level
        self.debug_mode = log_level in ["DEBUG", "TRACE"]
        self.all_test_items = []

    def pytest_collection_modifyitems(self, session, config, items):
        """Captures all available test items.

        Args:
            session: Pytest session
            config: Pytest configuration
            items: List of test items
        """
        self.all_test_items = items

    def pytest_runtest_protocol(self, item, nextitem):
        """Method called before running each test.

        Args:
            item: Test item to run
            nextitem: Next item to run
        """
        if self.debug_mode:
            logger.debug(f"Running test: {item.nodeid}")
        return None

    def pytest_runtest_logreport(self, report):
        """Method called for each test report.

        Args:
            report: pytest report
        """
        if report.when == "call" or (report.when == "setup" and report.failed):
            nodeid = report.nodeid
            status = TestStatus.PASS if report.passed else TestStatus.FAIL if report.failed else TestStatus.SKIPPED

            module_name = nodeid.split("::")[0].split("/")[-1].replace(".py", "")
            module_name = module_name.replace("test_", "").capitalize()

            test_name = nodeid.split("::")[-1].replace("test_", "").replace("_", " ").capitalize()

            message = ""
            if hasattr(report, "longrepr") and report.longrepr:
                if self.debug_mode:
                    message = str(report.longrepr)
                else:
                    if hasattr(report.longrepr, "reprcrash") and report.longrepr.reprcrash:
                        message = report.longrepr.reprcrash.message
                    else:
                        message = str(report.longrepr).split("\n")[-1] if "\n" in str(report.longrepr) else str(report.longrepr)

            test_result = TestResult(
                test_id=nodeid,
                name=f"{module_name}: {test_name}",
                status=status,
                message=message,
                duration=getattr(report, "duration", 0),
                module=module_name
            )
            self.results.append(test_result)

            color = get_status_color(status)

            if status == TestStatus.FAIL:
                if self.debug_mode:
                    logger.info(f"{color}{status.value}{COLOR_RESET} - {test_name}")
                    for line in message.split("\n"):
                        logger.debug(f"  {line}")
                else:
                    logger.info(f"{color}{status.value}{COLOR_RESET} - {test_name}")
            else:
                logger.info(f"{color}{status.value}{COLOR_RESET} - {test_name}")

    def pytest_report_teststatus(self, report, config):
        """Intercepts the status of each test.

        Args:
            report: Pytest report
            config: Pytest configuration
        """
        return None

    def pytest_terminal_summary(self, terminalreporter, exitstatus, config):
        """Captures the final summary of pytest.

        Args:
            terminalreporter: Pytest terminal report
            exitstatus: Exit status
            config: Pytest configuration
        """
        pass
