"""
Tests for connectivity between Wazuh services.
"""

import os
import pytest

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

@pytest.mark.connectivity
class TestConnectivity:
    """Tests for connectivity between Wazuh services."""

    def test_service_connectivity(self, config: AMITesterConfig):
        """Test connectivity between services using the configured tests."""
        connection = get_connection()

        successful_connections = []
        failed_connections = []
        message = ""

        for test in config.connectivity_tests:
            check_result = f"Connectivity: from {test.source} to {test.target} (host: {test.host}, port: {test.port})"

            exit_code, stdout, stderr = connection.execute_command(
                f"curl -v telnet://{test.host}:{test.port} 2>&1"
            )

            if exit_code == 0:
                check_result += " is successful (via curl)"
                successful_connections.append(check_result)

            else:
                exit_code, stdout, stderr = connection.execute_command(
                    f"echo '' | timeout 5 telnet {test.host} {test.port} 2>&1"
                )

                if "Connected to" in stdout or "Connected to" in stderr:
                    check_result += " is successful (via telnet)"
                    successful_connections.append(check_result)
                else:
                    check_result += " failed (both curl and telnet methods failed)"
                    failed_connections.append(check_result)

        if successful_connections or failed_connections:
            message += "Service connectivity test results:\n\n"

        if successful_connections:
            message += "Successful connections:\n- " + "\n- ".join(successful_connections) + "\n\n"

        if failed_connections:
            message += "Failed connections:\n- " + "\n- ".join(failed_connections) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if failed_connections:
            assert False, "One or more connectivity tests failed. " + message
        else:
            assert True, "All connectivity tests were successful. " + message

    def test_wazuh_api_connectivity(self, config: AMITesterConfig):
        """Test connectivity to the Wazuh API using configured api_endpoints."""
        connection = get_connection()

        successful_api_connections = []
        failed_api_connections = []
        skipped_services = []
        message = ""

        for service in config.services:
            if not service.api_endpoints:
                continue

            for endpoint_config in service.api_endpoints:
                url = endpoint_config.url
                token = endpoint_config.token
                auth = endpoint_config.auth
                headers = endpoint_config.headers

                endpoint_check_result = f"Endpoint: {url}"

                if not auth:
                    endpoint_check_result += " has no authentication configured - skipping"
                    skipped_services.append(endpoint_check_result)
                    continue

                generated_token = None
                if token:
                    token_command = f"curl -s -k -u {auth['username']}:{auth['password']} -X POST {token}"
                    endpoint_check_result += f" (attempting to get token from {token})"

                    exit_code, stdout, stderr = connection.execute_command(token_command)
                    if exit_code == 0 and stdout.strip():
                        generated_token = stdout.strip()
                        endpoint_check_result += f" - token obtained successfully"
                    else:
                        endpoint_check_result += f" - failed to obtain token: {stderr}"

                api_command = f'curl -s -k '

                if generated_token:
                    api_command += f'-H "Authorization: Bearer {generated_token}" '

                for header_name, header_value in headers.items():
                    api_command += f" -H '{header_name}: {header_value}'"

                api_command += f" -X GET -k {url} "

                endpoint_check_result += f" - attempting access"
                exit_code, stdout, stderr = connection.execute_command(api_command)

                if exit_code == 0 and ("token" in stdout or "data" in stdout):
                    endpoint_check_result += f" - successfully accessed with auth"
                    successful_api_connections.append(endpoint_check_result)
                else:
                    endpoint_check_result += f" - access failed: {stderr}"
                    failed_api_connections.append(endpoint_check_result)

        if successful_api_connections or failed_api_connections or skipped_services:
            message = "Wazuh API connectivity test results:\n\n"

        if successful_api_connections:
            message += "Successful API connections:\n- " + "\n- ".join(successful_api_connections) + "\n\n"

        if failed_api_connections:
            message += "Failed API connections:\n- " + "\n- ".join(failed_api_connections) + "\n\n"

        if skipped_services:
            message += "Skipped services (no API endpoints):\n- " + "\n- ".join(skipped_services) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if failed_api_connections:
            assert False, "One or more API connectivity tests failed. " + message
        elif not successful_api_connections and skipped_services:
            pytest.skip("No API endpoints were configured for testing. " + message)
        else:
            assert True, "All API connectivity tests were successful. " + message
