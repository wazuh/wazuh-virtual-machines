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

    return AMITesterConfig()

@pytest.mark.logs
class TestLogs:
    """Tests for Wazuh log files."""

    def test_log_files_exist(self, config: AMITesterConfig):
        """Test that all service log files exist."""
        connection = get_connection()

        existing_logs = []
        missing_logs = []

        for service_config in config.services:
            service_name = service_config.name
            for log_file in service_config.log_files:
                check_result = f"Log file: {log_file} (for {service_name})"
                exit_code, stdout, _ = connection.execute_command(
                    f"test -f {log_file} && echo 'EXISTS' || echo 'NOT_EXISTS'"
                )

                if stdout.strip() == "EXISTS":
                    check_result += " exists"
                    existing_logs.append(check_result)
                else:
                    check_result += " does NOT exist"
                    missing_logs.append(check_result)

        message = "\n\nResults:\n\n"

        if existing_logs:
            message += "Existing log files:\n- " + "\n- ".join(existing_logs) + "\n\n"

        if missing_logs:
            message += "Missing log files:\n- " + "\n- ".join(missing_logs) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if missing_logs:
            assert False, "One or more log files do not exist. " + message
        else:
            assert True, "All log files exist. " + message

    def test_logs_for_errors(self, config: AMITesterConfig):
        """Test logs for error messages."""
        connection = get_connection()
        error_patterns = config.log_error_patterns
        false_positives = config.log_false_positives

        clean_logs = []
        logs_with_errors = []
        skipped_logs = []

        for service_config in config.services:
            service_name = service_config.name

            for log_command in service_config.log_commands:
                check_result = f"Log command: {log_command} (for {service_name})"
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
                        error_summary = real_errors[:5]
                        if len(real_errors) > 5:
                            error_summary.append(f"...and {len(real_errors) - 5} more errors")

                        check_result += f" contains {len(real_errors)} errors: {error_summary}"
                        logs_with_errors.append(check_result)

                    else:
                        check_result += " contains no real errors (only false positives)"
                        clean_logs.append(check_result)
                else:
                    check_result += " contains no errors"
                    clean_logs.append(check_result)

            for log_file in service_config.log_files:
                if not log_file:
                    continue

                check_result = f"Log file: {log_file} (for {service_name})"
                exit_code, stdout, _ = connection.execute_command(
                    f"test -f {log_file} && echo 'EXISTS' || echo 'NOT_EXISTS'"
                )

                if stdout.strip() != "EXISTS":
                    check_result += " does not exist - skipping error check"
                    skipped_logs.append(check_result)
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
                        error_summary = real_errors[:5]
                        if len(real_errors) > 5:
                            error_summary.append(f"...and {len(real_errors) - 5} more errors")

                        check_result += f" contains {len(real_errors)} errors: {error_summary}"
                        logs_with_errors.append(check_result)

                    else:
                        check_result += " contains no real errors (only false positives)"
                        clean_logs.append(check_result)
                else:
                    check_result += " contains no errors"
                    clean_logs.append(check_result)

        message = "\n\nResults:\n\n"

        if clean_logs:
            message += "Clean logs (no errors):\n- " + "\n- ".join(clean_logs) + "\n\n"

        if logs_with_errors:
            message += "Logs with errors:\n- " + "\n- ".join(logs_with_errors) + "\n\n"

        if skipped_logs:
            message += "Skipped logs:\n- " + "\n- ".join(skipped_logs) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if skipped_logs and not logs_with_errors:
            pytest.skip("Some log files were skipped. " + message)

        if logs_with_errors:
            assert False, "Errors found in one or more logs. " + message
        else:
            assert True, "No errors found in logs. " + message

    def test_recent_logs(self, config: AMITesterConfig):
        """Test for recent errors in logs (last 24 hours)."""
        connection = get_connection()
        error_patterns = config.log_error_patterns
        false_positives = config.log_false_positives

        clean_recent_logs = []
        recent_logs_with_errors = []
        skipped_logs = []

        for service_config in config.services:
            service_name = service_config.name

            for log_command in service_config.log_commands:


                if "journalctl" in log_command and "--since" not in log_command:
                    recent_command = log_command.replace("journalctl", "journalctl --since '24 hours ago'")
                else:
                    recent_command = log_command

                check_result = f"Recent log command: {recent_command} (for {service_name})"
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
                        error_summary = real_errors[:5]
                        if len(real_errors) > 5:
                            error_summary.append(f"...and {len(real_errors) - 5} more errors")

                        check_result += f" contains recent errors: {error_summary}"
                        recent_logs_with_errors.append(check_result)

                    else:
                        check_result += " contains no real recent errors (only false positives)"
                        clean_recent_logs.append(check_result)
                else:
                    check_result += " contains no recent errors"
                    clean_recent_logs.append(check_result)

            for log_file in service_config.log_files:
                if not log_file:
                    continue



                check_result = f"Recent log file: {log_file} (for {service_name})"
                exit_code, stdout, _ = connection.execute_command(
                    f"test -f {log_file} && echo 'EXISTS' || echo 'NOT_EXISTS'"
                )

                if stdout.strip() != "EXISTS":
                    check_result += " does not exist - skipping recent error check"
                    skipped_logs.append(check_result)
                    continue

                command = (
                    f"find {log_file} -mtime -1 -type f -exec grep -l -E "
                    f"'{'|'.join(error_patterns)}' {{}} \\;"
                )

                exit_code, stdout, _ = connection.execute_command(command)

                if exit_code == 0 and stdout.strip():
                    files_with_errors = stdout.strip().split("\n")

                    for file_with_errors in files_with_errors:
                        file_check_result = f"Recent file: {file_with_errors} (for {service_name})"
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
                                error_summary = real_errors[:5]
                                if len(real_errors) > 5:
                                    error_summary.append(f"...and {len(real_errors) - 5} more errors")

                                file_check_result += f" contains recent errors: {error_summary}"
                                recent_logs_with_errors.append(file_check_result)

                            else:
                                file_check_result += " contains no real recent errors (only false positives)"
                                clean_recent_logs.append(file_check_result)
                        else:
                            file_check_result += " contains no recent errors"
                            clean_recent_logs.append(file_check_result)

                else:
                    check_result += " contains no recent errors"
                    clean_recent_logs.append(check_result)

        message = "\n\nResults:\n\n"

        if clean_recent_logs:
            message += "Clean recent logs (no errors):\n- " + "\n- ".join(clean_recent_logs) + "\n\n"

        if recent_logs_with_errors:
            message += "Recent logs with errors:\n- " + "\n- ".join(recent_logs_with_errors) + "\n\n"

        if skipped_logs:
            message += "Skipped logs:\n- " + "\n- ".join(skipped_logs) + "\n\n"


        print("\nTEST_DETAIL_MARKER:" + message)

        if skipped_logs and not recent_logs_with_errors:
            pytest.skip("Some log files were skipped. " + message)

        if recent_logs_with_errors:
            pytest.xfail("Recent errors found in logs (warning only). " + message)

        assert True, "No recent errors found in logs. " + message