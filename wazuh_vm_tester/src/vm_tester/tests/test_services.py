"""
Tests for Wazuh services.
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

@pytest.mark.services
class TestServices:
    """Tests for Wazuh services."""

    def test_services_active(self, config: AMITesterConfig):
        """Test that all services are active."""
        connection = get_connection()

        failures = []

        for service_config in config.services:
            service_name = service_config.name
            logger.info(f"Testing if service is active: {service_name}")

            exit_code, stdout, stderr = connection.execute_command(
                f"systemctl is-active {service_name}"
            )

            if exit_code != 0 or stdout.strip() != "active":
                failures.append(f"Service {service_name} is not active. Output: {stdout} {stderr}")
                logger.warning(f"Service {service_name} is not active. Output: {stdout} {stderr}")


        if failures:
            assert False, "\n".join(failures)

    def test_services_running(self, config: AMITesterConfig):
        """Test that all services are running."""
        connection = get_connection()

        failures = []

        for service_config in config.services:
            service_name = service_config.name
            logger.info(f"Testing if service is running: {service_name}")

            exit_code, stdout, stderr = connection.execute_command(
                f"systemctl status {service_name}"
            )

            if exit_code != 0 or "running" not in stdout:
                failures.append(f"Service {service_name} is not running. Output: {stdout[:100]}...")
                logger.warning(f"Service {service_name} is not running. Exit code: {exit_code}")

        if failures:
            assert False, "\n".join(failures)

    def test_required_directories(self, config: AMITesterConfig):
        """Test that required directories exist."""
        connection = get_connection()

        failures = []

        for service_config in config.services:
            service_name = service_config.name

            for directory in service_config.required_dirs:
                logger.info(f"Testing if directory exists: {directory} for {service_name}")

                exit_code, stdout, _ = connection.execute_command(
                    f"test -d {directory} && echo 'EXISTS' || echo 'NOT_EXISTS'"
                )

                if stdout.strip() != "EXISTS":
                    failures.append(f"Directory {directory} for {service_name} does not exist")
                    logger.warning(f"Directory {directory} for {service_name} does not exist")

        if failures:
            assert False, "\n".join(failures)

    def test_required_files(self, config: AMITesterConfig):
        """Test that required files exist."""
        connection = get_connection()
        failures = []

        for service_config in config.services:
            service_name = service_config.name

            for file_path in service_config.required_files:
                logger.info(f"Testing if file exists: {file_path} for {service_name}")

                exit_code, stdout, _ = connection.execute_command(
                    f"test -f {file_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
                )

                if stdout.strip() != "EXISTS":
                    failures.append(f"File {file_path} for {service_name} does not exist")
                    logger.warning(f"File {file_path} for {service_name} does not exist")

        if failures:
            assert False, "\n".join(failures)

    def test_ports_listening(self, config: AMITesterConfig):
        """Test that service ports are listening."""
        connection = get_connection()
        failures = []

        for service_config in config.services:
            if not service_config.port:
                continue

            service_name = service_config.name
            ports = []
            if isinstance(service_config.port, list):
                ports = service_config.port
            else:
                ports = [service_config.port]

            for port in ports:
                logger.info(f"Testing if port is listening: {port} for {service_name}")

                exit_code, stdout, _ = connection.execute_command(
                    f"netstat -tuln | grep -E ':{port}\\s'"
                )

                if exit_code != 0 or not stdout.strip():

                    exit_code, stdout, _ = connection.execute_command(
                        f"ss -tuln | grep -E ':{port}\\s'"
                    )

                if exit_code != 0 or not stdout.strip():
                    failures.append(f"Port {port} for {service_name} is not listening")
                    logger.warning(f"Port {port} for {service_name} is not listening")

        if failures:
            assert False, "\n".join(failures)

    def test_health_endpoints(self, config: AMITesterConfig):
        """Test health_endpoints of services."""
        connection = get_connection()
        failures = []

        for service_config in config.services:
            service_name = service_config.name

            for endpoint_config in service_config.health_endpoints:
                url = endpoint_config.url
                auth = endpoint_config.auth
                headers = endpoint_config.headers
                expected_status = endpoint_config.expected_status

                logger.info(f"Testing endpoint: {url} for {service_name}")

                if auth:
                    command = f"curl -s -k -u {auth['username']}:{auth['password']} -o /dev/null -w '%{{http_code}}' {url}"
                else:
                    command = f"curl -s -k -o /dev/null -w '%{{http_code}}' {url}"

                for header_name, header_value in headers.items():
                    command += f" -H '{header_name}: {header_value}'"

                exit_code, stdout, stderr = connection.execute_command(command)
                http_code = stdout.strip()

                if exit_code != 0 or int(http_code) not in expected_status:
                    failures.append(
                        f"Endpoint {url} for {service_name} "
                        f"failed with code {http_code}. Error: {stderr}"
                    )
                    logger.warning(
                        f"Endpoint {url} for {service_name} "
                        f"failed with code {http_code}. Error: {stderr}"
                    )

        if failures:
            assert False, "\n".join(failures)
