"""
Tests for Wazuh log files.
"""

import os
import pytest
import re

from ..config import AMITesterConfig
from ..utils.logger import get_logger
from ..connections.pytest_connector import get_connection

logger = get_logger(__name__)


@pytest.fixture(scope="module")
def config() -> AMITesterConfig:
    """Create test configuration from environment variables.

    Returns:
        AMITesterConfig with expected values
    """
    expected_version = os.environ.get("WAZUH_EXPECTED_VERSION")
    expected_revision = os.environ.get("WAZUH_EXPECTED_REVISION")

    return AMITesterConfig(
        expected_version=expected_version,
        expected_revision=expected_revision
    )

@pytest.mark.logs
class TestLogs:
    """Tests for Wazuh log files."""

    def test_log_files_exist(self, config: AMITesterConfig):
        """Test that all service log files exist."""
        connection = get_connection()

        failures = []

        for service_config in config.services:
            service_name = service_config.name
            for log_file in service_config.log_files:
                logger.info(f"Testing if log file exists: {log_file} for {service_name}")

                exit_code, stdout, _ = connection.execute_command(
                    f"test -f {log_file} && echo 'EXISTS' || echo 'NOT_EXISTS'"
                )

                if stdout.strip() != "EXISTS":
                    failures.append(f"Log file {log_file} for {service_name} does not exist")
                    logger.warning(f"Log file {log_file} for {service_name} does not exist")

        if failures:
            assert False, "\n".join(failures)

    def test_logs_for_errors(self, config: AMITesterConfig):
        """Test logs for error messages."""
        connection = get_connection()
        error_patterns = config.log_error_patterns
        false_positives = config.log_false_positives

        failures = []
        skipped_logs = []

        for service_config in config.services:
            service_name = service_config.name

            for log_command in service_config.log_commands:
                logger.info(f"Checking for errors using command: {log_command} for {service_name}")

                error_patterns_str = "|".join(error_patterns)

                if "grep" in log_command:
                    command = log_command
                else:
                    command = f"{log_command} | grep -E '{error_patterns_str}'"

                exit_code, stdout, _ = connection.execute_command(command)

                if exit_code == 0 and stdout.strip():
                    lines = stdout.strip().split("\n")
                    real_errors = []

                    for line in lines:
                        is_false_positive = any(re.search(fp, line) for fp in false_positives)
                        if not is_false_positive:
                            real_errors.append(line.strip())

                    if real_errors:
                        error_msg = (
                            f"Found {len(real_errors)} errors using command '{log_command}' for {service_name}: "
                            f"{real_errors[:10]}"
                        ) + (f" and {len(real_errors) - 10} more..." if len(real_errors) > 10 else "")
                        failures.append(error_msg)
                        logger.warning(error_msg)

            for log_file in service_config.log_files:
                if not log_file:
                    continue

                logger.info(f"Checking for errors in log file: {log_file} for {service_name}")

                exit_code, stdout, _ = connection.execute_command(
                    f"test -f {log_file} && echo 'EXISTS' || echo 'NOT_EXISTS'"
                )

                if stdout.strip() != "EXISTS":
                    skipped_logs.append(f"Log file {log_file} does not exist - skipping error check")
                    logger.warning(f"Log file {log_file} does not exist - skipping error check")
                    continue

                error_patterns_str = "|".join(error_patterns)
                grep_command = f"grep -E '{error_patterns_str}' {log_file}"

                exit_code, stdout, _ = connection.execute_command(grep_command)

                if exit_code == 0 and stdout.strip():
                    lines = stdout.strip().split("\n")
                    real_errors = []

                    for line in lines:
                        is_false_positive = any(re.search(fp, line) for fp in false_positives)

                        if not is_false_positive:
                            real_errors.append(line.strip())

                    if real_errors:
                        error_msg = f"Found {len(real_errors)} errors in log {log_file} for {service_name}: " \
                                f"{real_errors[:10]}" + \
                                (f" and {len(real_errors) - 10} more..." if len(real_errors) > 10 else "")
                        failures.append(error_msg)
                        logger.warning(error_msg)

        if skipped_logs and not failures:
            pytest.skip("\n".join(skipped_logs))

        if failures:
            assert False, "\n".join(failures)

    def test_recent_logs(self, config: AMITesterConfig):
        """Test for recent errors in logs (last 24 hours)."""
        connection = get_connection()

        error_patterns = config.log_error_patterns
        false_positives = config.log_false_positives

        failures = []
        skipped_logs = []
        warnings = []

        for service_config in config.services:
            service_name = service_config.name

            for log_command in service_config.log_commands:
                logger.info(f"Checking for recent errors using command: {log_command} for {service_name}")

                if "journalctl" in log_command and "--since" not in log_command:
                    recent_command = log_command.replace("journalctl", "journalctl --since '24 hours ago'")
                else:
                    recent_command = log_command

                error_patterns_str = "|".join(error_patterns)


                if "grep" in recent_command:
                    command = recent_command
                else:
                    command = f"{recent_command} | grep -E '{error_patterns_str}'"

                exit_code, stdout, _ = connection.execute_command(command)

                if exit_code == 0 and stdout.strip():
                    lines = stdout.strip().split("\n")
                    real_errors = []

                    for line in lines:
                        is_false_positive = any(re.search(fp, line) for fp in false_positives)
                        if not is_false_positive:
                            real_errors.append(line.strip())

                    if real_errors:
                        error_msg = (
                            f"Found recent errors using command '{recent_command}' for {service_name}: "
                            f"{real_errors[:5]}"
                        )
                        warnings.append(error_msg)
                        logger.warning(error_msg)

            for log_file in service_config.log_files:
                if not log_file:
                    continue

                logger.info(f"Checking for recent errors in log file: {log_file} for {service_name}")

                exit_code, stdout, _ = connection.execute_command(
                    f"test -f {log_file} && echo 'EXISTS' || echo 'NOT_EXISTS'"
                )

                if stdout.strip() != "EXISTS":
                    skipped_logs.append(f"Log file {log_file} does not exist - skipping recent error check")
                    logger.warning(f"Log file {log_file} does not exist - skipping recent error check")
                    continue

                command = (
                    f"find {log_file} -mtime -1 -type f -exec grep -l -E "
                    f"'{'|'.join(error_patterns)}' {{}} \\;"
                )

                exit_code, stdout, _ = connection.execute_command(command)

                if exit_code == 0 and stdout.strip():
                    files_with_errors = stdout.strip().split("\n")

                    for file_with_errors in files_with_errors:
                        error_patterns_str = "|".join(error_patterns)
                        grep_command = f"grep -E '{error_patterns_str}' {file_with_errors}"

                        exit_code, stdout, _ = connection.execute_command(grep_command)

                        if exit_code == 0 and stdout.strip():
                            lines = stdout.strip().split("\n")
                            real_errors = []

                            for line in lines:
                                is_false_positive = any(re.search(fp, line) for fp in false_positives)

                                if not is_false_positive:
                                    real_errors.append(line.strip())

                            if real_errors:
                                error_msg = f"Found recent errors in {file_with_errors}: {real_errors[:5]}"
                                warnings.append(error_msg)
                                logger.warning(error_msg)

        if skipped_logs and not failures and not warnings:
            pytest.skip("\n".join(skipped_logs))

        if warnings:
            pytest.xfail("\n".join(warnings))

        if failures:
            assert False, "\n".join(failures)
