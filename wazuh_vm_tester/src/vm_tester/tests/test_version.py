"""
Tests for Wazuh version and revision.
"""

import re

import pytest

from ..config import AMITesterConfig
from ..connections.pytest_connector import get_connection
from ..utils.logger import get_logger

logger = get_logger(__name__)


def config() -> AMITesterConfig:
    """Create test configuration from environment variables.

    Returns:
        AMITesterConfig with expected values
    """
    return AMITesterConfig()


@pytest.mark.version
class TestVersion:
    """Tests for Wazuh version and revision."""

    def test_services_versions(self, config: AMITesterConfig):
        """Test the version of all Wazuh services."""
        connection = get_connection()
        services_to_test = ["wazuh-server", "wazuh-indexer", "wazuh-dashboard"]

        all_commands_results = []
        successful_commands = []
        failed_commands = []

        for service_name in services_to_test:
            service_config = next((s for s in config.services if s.name == service_name), None)
            if not service_config:
                failed_commands.append(f"Service {service_name} configuration not found")
                continue

            expected_version = service_config.version
            if not expected_version:
                all_commands_results.append(f"Skipping version check for {service_name} - no expected version set")
                continue

            for cmd_config in service_config.version_commands:
                exit_code, stdout, stderr = connection.execute_command(cmd_config.command)

                cmd_result = f"Command: {cmd_config.command}"

                if exit_code != 0 or not stdout.strip():
                    if exit_code != 0:
                        cmd_result += f" failed with error: {stderr}"
                    else:
                        cmd_result += " returned empty output"

                    all_commands_results.append(cmd_result)
                    failed_commands.append(cmd_result)
                    continue

                if cmd_config.expected_regex:
                    version_match = re.search(cmd_config.expected_regex, stdout)
                    if version_match:
                        detected_version = version_match.group(1)
                        cmd_result += f" found version: {detected_version}"

                        if expected_version in detected_version:
                            cmd_result += f" (matches expected: {expected_version})"
                            successful_commands.append(cmd_result)
                        else:
                            cmd_result += f" (does NOT match expected: {expected_version})"
                            failed_commands.append(cmd_result)
                    else:
                        cmd_result += f" no version match found using regex: '{cmd_config.expected_regex}'"
                        failed_commands.append(cmd_result)
                elif cmd_config.expected_output and cmd_config.expected_output in stdout:
                    cmd_result += f" found expected output: '{cmd_config.expected_output}'"
                    successful_commands.append(cmd_result)
                else:
                    detected_output = stdout.strip()
                    cmd_result += f" returned output: {detected_output}"
                    if expected_version in detected_output:
                        cmd_result += f" (contains expected version: {expected_version})"
                        successful_commands.append(cmd_result)
                    else:
                        cmd_result += f" (does NOT contain expected version: {expected_version})"
                        failed_commands.append(cmd_result)

        message = "Version commands results:\n\n"

        if successful_commands:
            message += "Successful commands:\n- " + "\n- ".join(successful_commands) + "\n\n"

        if failed_commands:
            message += "Failed commands:\n- " + "\n- ".join(failed_commands) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if failed_commands:
            raise AssertionError("One or more version commands failed. " + message)
        elif not successful_commands:
            pytest.skip("No version commands were executed successfully. " + message)
        else:
            assert True, "All version commands successful. " + message

    def test_services_revisions(self, config: AMITesterConfig):
        """Test the revision of all Wazuh services."""
        connection = get_connection()
        services_to_test = ["wazuh-server", "wazuh-indexer", "wazuh-dashboard"]

        all_commands_results = []
        successful_commands = []
        failed_commands = []
        message = ""

        for service_name in services_to_test:
            service_config = next((s for s in config.services if s.name == service_name), None)
            if not service_config:
                failed_commands.append(f"Service {service_name} configuration not found")
                continue

            expected_revision = service_config.revision
            if not expected_revision:
                all_commands_results.append(f"Skipping revision check for {service_name} - no expected revision set")
                continue

            for cmd_config in service_config.revision_commands:
                exit_code, stdout, stderr = connection.execute_command(cmd_config.command)

                cmd_result = f"Command: {cmd_config.command}"

                if exit_code != 0 or not stdout.strip():
                    if exit_code != 0:
                        cmd_result += f" failed with error: {stderr}"
                    else:
                        cmd_result += " returned empty output"

                    all_commands_results.append(cmd_result)
                    failed_commands.append(cmd_result)
                    continue

                if cmd_config.expected_regex:
                    revision_match = re.search(cmd_config.expected_regex, stdout)
                    if revision_match:
                        detected_revision = revision_match.group(1)
                        cmd_result += f" found revision: {detected_revision}"

                        if expected_revision in detected_revision:
                            cmd_result += f" (matches expected: {expected_revision})"
                            successful_commands.append(cmd_result)
                        else:
                            cmd_result += f" (does NOT match expected: {expected_revision})"
                            failed_commands.append(cmd_result)
                    else:
                        cmd_result += f" no revision match found using regex: '{cmd_config.expected_regex}'"
                        failed_commands.append(cmd_result)
                else:
                    detected_revision = stdout.strip()
                    cmd_result += f" found revision: {detected_revision}"

                    if expected_revision in detected_revision:
                        cmd_result += f" (matches expected: {expected_revision})"
                        successful_commands.append(cmd_result)
                    else:
                        cmd_result += f" (does NOT match expected: {expected_revision})"
                        failed_commands.append(cmd_result)

        if successful_commands or failed_commands:
            message += "Revision commands results:\n\n"

        if successful_commands:
            message += "Successful commands:\n- " + "\n- ".join(successful_commands) + "\n\n"

        if failed_commands:
            message += "Failed commands:\n- " + "\n- ".join(failed_commands) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if failed_commands:
            raise AssertionError("One or more revision commands failed. " + message)
        elif not successful_commands:
            pytest.skip("No revision commands were executed successfully. " + message)
        else:
            assert True, "All revision commands successful. " + message
