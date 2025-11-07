"""
Module to collect test results from pytest.
"""

from ..utils.logger import get_logger
from .base import COLOR_RESET, TestResult, TestStatus, get_status_color

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

            if hasattr(report, "wasxfail"):
                status = TestStatus.WARNING
            elif report.passed:
                status = TestStatus.PASS
            elif report.failed:
                status = TestStatus.FAIL
            elif report.skipped:
                status = TestStatus.SKIPPED
            else:
                status = TestStatus.ERROR

            module_name = nodeid.split("::")[0].split("/")[-1].replace(".py", "")
            module_name = module_name.replace("test_", "").capitalize()

            test_name = nodeid.split("::")[-1].replace("test_", "").replace("_", " ").capitalize()

            class_name = None
            method_name = None
            if "::" in nodeid:
                parts = nodeid.split("::")
                if len(parts) > 2:
                    class_name = parts[1]
                    method_name = parts[2]

            message = ""
            if hasattr(report, "wasxfail") and report.wasxfail:
                message = report.wasxfail
            elif report.passed:
                if hasattr(report, "longrepr") and report.longrepr:
                    message = str(report.longrepr)

                if not message and hasattr(report, "capstdout") and report.capstdout:
                    stdout = report.capstdout
                    if "TEST_DETAIL_MARKER:" in stdout and self.debug_mode:
                        message = stdout.split("TEST_DETAIL_MARKER:", 1)[1].strip()

                if not message and class_name and method_name:
                    try:
                        import importlib

                        module = importlib.import_module(f"vm_tester.tests.{module_name.lower()}")
                        test_class = getattr(module, class_name)

                        if hasattr(test_class, "test_results") and method_name in test_class.test_results:
                            message = test_class.test_results[method_name]
                    except Exception as e:
                        logger.debug(f"Error trying to get test result from class: {e}")

                if not message:

                    try:
                        with open("vm_tester.log") as f:
                            log_lines = f.readlines()

                        recent_logs = []
                        for line in log_lines:
                            if "All revision tests passed" in line:
                                recent_logs.append(line.split(" - ")[-1].strip())

                        if recent_logs:
                            message = recent_logs[-1]
                    except Exception as e:
                        logger.debug(f"Error trying to get test result from log: {e}")

            elif hasattr(report, "longrepr") and report.longrepr:
                if self.debug_mode:
                    message = str(report.longrepr)
                else:
                    if hasattr(report.longrepr, "reprcrash") and report.longrepr.reprcrash:
                        message = report.longrepr.reprcrash.message
                    else:
                        message = str(report.longrepr)

            test_result = TestResult(
                test_id=nodeid,
                name=f"{module_name}: {test_name}",
                status=status,
                message=message,
                duration=getattr(report, "duration", 0),
                module=module_name,
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
            elif status == TestStatus.WARNING and hasattr(report, "wasxfail"):
                logger.info(f"{color}{status.value}{COLOR_RESET} - {test_name} (xfailed)")
                if self.debug_mode:
                    for line in message.split("\n"):
                        logger.debug(f"  {line}")
            elif status == TestStatus.PASS and message:
                logger.info(f"{color}{status.value}{COLOR_RESET} - {test_name}")
                if self.debug_mode:
                    logger.debug("  Test details:")
                    for line in message.split("\n"):
                        logger.debug(f"  {line}")
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
