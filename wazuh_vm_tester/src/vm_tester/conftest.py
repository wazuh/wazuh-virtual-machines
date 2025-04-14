"""
Pytest configuration and fixtures for wazuh_vm_tester.
"""

import os
import pytest
import sys
from pathlib import Path
from typing import Any

src_dir = Path(__file__).parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from .config import AMITesterConfig, get_logger
from .connections.pytest_connector import get_connection

logger = get_logger(__name__)


def pytest_addoption(parser):
    """Add custom command-line options to pytest."""

    parser.addoption(
        "--ssh-host",
        action="store",
        help="Host to connect to via SSH"
    )
    parser.addoption(
        "--ssh-username",
        action="store",
        default="wazuh-user",
        help="SSH username (default: wazuh-user)"
    )
    parser.addoption(
        "--ssh-key",
        action="store",
        help="Path to SSH private key"
    )
    parser.addoption(
        "--ssh-port",
        action="store",
        default="22",
        help="SSH port (default: 22)"
    )

    parser.addoption(
        "--use-local",
        action="store_true",
        help="Use local machine for testing"
    )

    parser.addoption(
        "--expected-version",
        action="store",
        help="Expected Wazuh version"
    )
    parser.addoption(
        "--expected-revision",
        action="store",
        help="Expected revision"
    )

    parser.addoption(
        "--json",
        action="store",
        help="Path to save JSON output"
    )
    parser.addoption(
        "--github",
        action="store",
        help="Path to save GitHub-compatible output"
    )


@pytest.fixture(scope="session")
def config(request) -> AMITesterConfig:
    """Create test configuration from command-line arguments.

    Args:
        request: Pytest request object

    Returns:
        AMITesterConfig object
    """
    ssh_host = request.config.getoption("--ssh-host")
    ssh_username = request.config.getoption("--ssh-username")
    ssh_key = request.config.getoption("--ssh-key")
    ssh_port = int(request.config.getoption("--ssh-port"))
    use_local = request.config.getoption("--use-local")
    expected_version = request.config.getoption("--expected-version")
    expected_revision = request.config.getoption("--expected-revision")

    if not ssh_host and not use_local:
        expected_version = expected_version or os.environ.get("WAZUH_EXPECTED_VERSION")
        expected_revision = expected_revision or os.environ.get("WAZUH_EXPECTED_REVISION")

    if use_local:
        return AMITesterConfig(
            use_local=True,
            expected_version=expected_version,
            expected_revision=expected_revision
        )
    elif ssh_host:
        return AMITesterConfig(
            ssh_host=ssh_host,
            ssh_username=ssh_username,
            ssh_key_path=ssh_key,
            ssh_port=ssh_port,
            expected_version=expected_version,
            expected_revision=expected_revision
        )
    else:
        return AMITesterConfig(
            expected_version=expected_version,
            expected_revision=expected_revision
        )


@pytest.fixture(scope="session")
def instance() -> Any:
    """Use active connection for testing.

    Returns:
        Connected instance for testing
    """
    return get_connection()
