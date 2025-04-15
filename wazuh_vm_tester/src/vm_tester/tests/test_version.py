"""
Tests for Wazuh version and revision.
"""

import os
import pytest
import re
from typing import Dict, List, Optional

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

@pytest.mark.version
class TestVersion:
    """Tests for Wazuh version and revision."""

    def test_services_versions(self, config: AMITesterConfig):
        """Test the version of all Wazuh services."""
        connection = get_connection()
        services_to_test = ["wazuh-server", "wazuh-indexer", "wazuh-dashboard"]

        for service_name in services_to_test:
            logger.info(f"Testing {service_name} version")

            service_config = next((s for s in config.services if s.name == service_name), None)
            if not service_config:
                pytest.fail(f"{service_name} configuration not found")
                continue

            version_found = False
            detected_version = None

            for cmd_config in service_config.version_commands:
                exit_code, stdout, stderr = connection.execute_command(cmd_config.command)

                if exit_code != 0:
                    logger.warning(f"Command failed for {service_name}: {cmd_config.command}, error: {stderr}")
                    continue
                expected_version = service_config.version

                if cmd_config.expected_regex:
                    version_match = re.search(cmd_config.expected_regex, stdout)
                    if version_match:
                        detected_version = version_match.group(1)
                        logger.info(f"Detected {service_name} version: {detected_version}")
                        version_found = True
                        break
                elif cmd_config.expected_output and cmd_config.expected_output in stdout:
                    logger.info(f"Detected expected output in version command for {service_name}: {cmd_config.command}")
                    version_found = True
                    break

            if not version_found:
                pytest.fail(f"Could not extract {service_name} version from any configured command")
                continue

            if expected_version not in detected_version:
                pytest.fail(
                    f"{service_name} version ({detected_version}) might not be compatible "
                    f"with expected Wazuh version ({expected_version})"
                )

            logger.info(f"{service_name} version check passed")
