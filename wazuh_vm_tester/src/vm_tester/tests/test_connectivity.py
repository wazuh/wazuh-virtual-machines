"""
Tests for connectivity between Wazuh services.
"""

import os
import pytest

from ..config import AMITesterConfig, get_logger
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

@pytest.mark.connectivity
class TestConnectivity:
    """Tests for connectivity between Wazuh services."""

    def test_service_connectivity(self, config: AMITesterConfig):
        """Test connectivity between services using the configured tests."""
        connection = get_connection()
        failures = []

        for test in config.connectivity_tests:
            logger.info(f"Testing connectivity: from {test.source} to {test.target} by (port {test.port})")
            exit_code, stdout, stderr = connection.execute_command(
                f"curl -v telnet://{test.host}:{test.port} 2>&1"
            )

            if exit_code == 0:
                logger.info(f"Connectivity test passed: from {test.source} to {test.target} by (port {test.port})")
            else:
                exit_code, stdout, stderr = connection.execute_command(
                    f"echo '' | timeout 5 telnet {test.host} {test.port} 2>&1"
                )

                if "Connected to" not in stdout and "Connected to" not in stderr:
                    failures.append(f"Connectivity failure: from {test.source} to {test.target} by (port {test.port})")
                    logger.warning(f"Connectivity failure: from {test.source} to {test.target} by (port {test.port})")

        if failures:
            assert False, "\n".join(failures)

    def test_wazuh_api_connectivity(self, config: AMITesterConfig):
        """Test connectivity to the Wazuh API using configured api_endpoints."""
        connection = get_connection()
        failures = []

        for service in config.services:
            if not service.api_endpoints:
                continue
            logger.info(f"Testing API connectivity for service: {service.name}")

            api_access_successful = False
            for endpoint_config in service.api_endpoints:
                url = endpoint_config.url
                token = endpoint_config.token
                auth = endpoint_config.auth
                headers = endpoint_config.headers

                if not auth:
                    continue
                else:
                    if token:
                        command = f"curl -s -k -u {auth['username']}:{auth['password']} -X POST {token}"
                        exit_code, stdout, stderr = connection.execute_command(command)
                        if exit_code == 0:
                            generated_token = stdout

                    command = f'curl -s -k '

                    if generated_token:
                        command += f'-H "Authorization: Bearer {generated_token}" '

                    for header_name, header_value in headers.items():
                        command += f" -H '{header_name}: {header_value}'"

                    command += f" -X GET -k {url} "

                    logger.info(f"Trying API access with configured auth to {url}")

                    exit_code, stdout, stderr = connection.execute_command(command)

                    if exit_code == 0 and ("token" in stdout or "data" in stdout):
                        logger.info(f"API endpoint {url} is accessible with configured auth")
                        api_access_successful = True
                        break

                if api_access_successful:
                    break

            if not api_access_successful and service.api_endpoints:
                failures.append(f"API access failed for service {service.name}, endpoint {url}, with command {command}, using {generated_token}: no endpoint was accessible")

        if failures:
            assert False, "\n".join(failures)
