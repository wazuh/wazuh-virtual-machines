"""
Tests for Wazuh services.
"""

import pytest

from ..config import AMITesterConfig
from ..connections.pytest_connector import get_connection
from ..utils.logger import get_logger

logger = get_logger(__name__)


@pytest.fixture(scope="module")
def config() -> AMITesterConfig:
    """Create test configuration from environment variables.

    Returns:
        AMITesterConfig with expected values
    """

    return AMITesterConfig()


@pytest.mark.services
class TestServices:
    """Tests for Wazuh services."""

    def test_services_active(self, config: AMITesterConfig):
        """Test that all services are active."""
        connection = get_connection()

        successful_checks = []
        failed_checks = []

        for service_config in config.services:
            service_name = service_config.name

            check_result = f"Service: {service_name}"
            exit_code, stdout, stderr = connection.execute_command(f"systemctl is-active {service_name}")

            if exit_code == 0 and stdout.strip() == "active":
                check_result += " is active"
                successful_checks.append(check_result)
            else:
                check_result += f" is NOT active. Output: {stdout} {stderr}"
                failed_checks.append(check_result)

        message = "\nResults:\n\n"

        if successful_checks:
            message += "Active services:\n- " + "\n- ".join(successful_checks) + "\n\n"

        if failed_checks:
            message += "Inactive services:\n- " + "\n- ".join(failed_checks) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if failed_checks:
            raise AssertionError("One or more services are not active. " + message)
        else:
            assert True, "All services are active. " + message

    def test_services_running(self, config: AMITesterConfig):
        """Test that all services are running."""
        connection = get_connection()

        successful_checks = []
        failed_checks = []

        for service_config in config.services:
            service_name = service_config.name

            check_result = f"Service: {service_name}"
            exit_code, stdout, stderr = connection.execute_command(f"systemctl status {service_name}")

            if exit_code == 0 and "running" in stdout:
                check_result += " is running"
                successful_checks.append(check_result)
            else:
                status_output = stdout[:100] + "..." if len(stdout) > 100 else stdout
                check_result += f" is NOT running. Status: {status_output}"
                failed_checks.append(check_result)

        message = "Service running state results:\n\n"

        if successful_checks:
            message += "Running services:\n- " + "\n- ".join(successful_checks) + "\n\n"

        if failed_checks:
            message += "Non-running services:\n- " + "\n- ".join(failed_checks) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if failed_checks:
            raise AssertionError("One or more services are not running. " + message)
        else:
            assert True, "All services are running. " + message

    def test_required_directories(self, config: AMITesterConfig):
        """Test that required directories exist."""
        connection = get_connection()

        existing_dirs = []
        missing_dirs = []

        for service_config in config.services:
            service_name = service_config.name
            for directory in service_config.required_dirs:
                check_result = f"Directory: {directory} (for {service_name})"
                exit_code, stdout, _ = connection.execute_command(
                    f"test -d {directory} && echo 'EXISTS' || echo 'NOT_EXISTS'"
                )

                if stdout.strip() == "EXISTS":
                    check_result += " exists"
                    existing_dirs.append(check_result)
                else:
                    check_result += " does NOT exist"
                    missing_dirs.append(check_result)

        message = "Directory existence check results:\n\n"

        if existing_dirs:
            message += "Existing directories:\n- " + "\n- ".join(existing_dirs) + "\n\n"

        if missing_dirs:
            message += "Missing directories:\n- " + "\n- ".join(missing_dirs) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if missing_dirs:
            raise AssertionError("One or more required directories do not exist. " + message)
        else:
            assert True, "All required directories exist. " + message

    def test_required_files(self, config: AMITesterConfig):
        """Test that required files exist."""
        connection = get_connection()

        existing_files = []
        missing_files = []

        for service_config in config.services:
            service_name = service_config.name
            for file_path in service_config.required_files:
                check_result = f"File: {file_path} (for {service_name})"
                exit_code, stdout, _ = connection.execute_command(
                    f"test -f {file_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
                )

                if stdout.strip() == "EXISTS":
                    check_result += " exists"
                    existing_files.append(check_result)
                else:
                    check_result += " does NOT exist"
                    missing_files.append(check_result)

        message = "File existence check results:\n\n"

        if existing_files:
            message += "Existing files:\n- " + "\n- ".join(existing_files) + "\n\n"

        if missing_files:
            message += "Missing files:\n- " + "\n- ".join(missing_files) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if missing_files:
            raise AssertionError("One or more required files do not exist. " + message)
        else:
            assert True, "All required files exist. " + message

    def test_ports_listening(self, config: AMITesterConfig):
        """Test that service ports are listening."""
        connection = get_connection()

        listening_ports = []
        not_listening_ports = []

        for service_config in config.services:
            if not service_config.port:
                continue

            service_name = service_config.name
            ports = []
            ports = service_config.port if isinstance(service_config.port, list) else [service_config.port]

            for port in ports:
                check_result = f"Port: {port} (for {service_name})"
                exit_code, stdout, _ = connection.execute_command(f"netstat -tuln | grep -E ':{port}\\s'")

                if exit_code != 0 or not stdout.strip():
                    exit_code, stdout, _ = connection.execute_command(f"ss -tuln | grep -E ':{port}\\s'")

                if exit_code == 0 and stdout.strip():
                    check_result += " is listening"
                    listening_ports.append(check_result)
                else:
                    check_result += " is NOT listening"
                    not_listening_ports.append(check_result)

        message = "Port listening check results:\n\n"

        if listening_ports:
            message += "Listening ports:\n- " + "\n- ".join(listening_ports) + "\n\n"

        if not_listening_ports:
            message += "Non-listening ports:\n- " + "\n- ".join(not_listening_ports) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if not_listening_ports:
            raise AssertionError("One or more ports are not listening. " + message)
        else:
            assert True, "All ports are listening. " + message

    def test_health_endpoints(self, config: AMITesterConfig):
        """Test health_endpoints of services."""
        connection = get_connection()

        successful_endpoints = []
        failed_endpoints = []

        for service_config in config.services:
            service_name = service_config.name
            for endpoint_config in service_config.health_endpoints:
                url = endpoint_config.url
                auth = endpoint_config.auth
                headers = endpoint_config.headers
                expected_status = endpoint_config.expected_status
                check_result = f"Endpoint: {url} (for {service_name})"

                if auth:
                    command = (
                        f"curl -s -k -u {auth['username']}:{auth['password']} -o /dev/null -w '%{{http_code}}' {url}"
                    )
                else:
                    command = f"curl -s -k -o /dev/null -w '%{{http_code}}' {url}"

                for header_name, header_value in headers.items():
                    command += f" -H '{header_name}: {header_value}'"

                exit_code, stdout, stderr = connection.execute_command(command)
                http_code = stdout.strip()

                if exit_code == 0 and int(http_code) in expected_status:
                    check_result += f" returned status {http_code} (expected: {', '.join(map(str, expected_status))})"
                    successful_endpoints.append(check_result)
                else:
                    check_result += f" failed with status {http_code} (expected: {', '.join(map(str, expected_status))}). Error: {stderr}"
                    failed_endpoints.append(check_result)
                    logger.warning(f"Endpoint {url} for {service_name} failed with code {http_code}. Error: {stderr}")

        message = "Health endpoint check results:\n\n"

        if successful_endpoints:
            message += "Successful endpoints:\n- " + "\n- ".join(successful_endpoints) + "\n\n"

        if failed_endpoints:
            message += "Failed endpoints:\n- " + "\n- ".join(failed_endpoints) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if failed_endpoints:
            raise AssertionError("One or more health endpoints failed. " + message)
        else:
            assert True, "All health endpoints are accessible. " + message
