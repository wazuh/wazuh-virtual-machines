"""
Tests specific to OVA validation.
"""

import os
import pytest

from ..config import BaseTesterConfig, OVATesterConfig
from ..utils.logger import get_logger
from ..connections.pytest_connector import get_connection
logger = get_logger(__name__)

@pytest.fixture(scope="module")
def config() -> BaseTesterConfig:
    """Create test configuration from environment variables.

    Returns:
        BaseTesterConfig with expected values
    """
    return BaseTesterConfig()

@pytest.mark.ova
class TestOVA:
    """Tests specific to OVA validation."""

    def test_1(self, config: BaseTesterConfig):
        """Test ......"""
        connection = get_connection()

        # Check if hardware virtualization is enabled
        exit_code, stdout, stderr = connection.execute_command(
            ""
        )

        if exit_code == 0 and stdout.strip():
            assertion_message = ""
        else:
            assertion_message = ""

        print("\nTEST_DETAIL_MARKER:" + assertion_message)
        assert exit_code == 0 and stdout.strip(), assertion_message

    def test_2(self, config: BaseTesterConfig):
        """Test ......"""
        connection = get_connection()

        # Check if hardware virtualization is enabled
        exit_code, stdout, stderr = connection.execute_command(
            ""
        )

        if exit_code == 0 and stdout.strip():
            assertion_message = ""
        else:
            assertion_message = ""

        print("\nTEST_DETAIL_MARKER:" + assertion_message)
        assert exit_code == 0 and stdout.strip(), assertion_message

    def test_3(self, config: BaseTesterConfig):
        """Test ......"""
        connection = get_connection()

        # Check if hardware virtualization is enabled
        exit_code, stdout, stderr = connection.execute_command(
            ""
        )

        if exit_code == 0 and stdout.strip():
            assertion_message = ""
        else:
            assertion_message = ""

        print("\nTEST_DETAIL_MARKER:" + assertion_message)
        assert exit_code == 0 and stdout.strip(), assertion_message

    def test_4(self, config: BaseTesterConfig):
        """Test ......"""
        connection = get_connection()

        # Check if hardware virtualization is enabled
        exit_code, stdout, stderr = connection.execute_command(
            ""
        )

        if exit_code == 0 and stdout.strip():
            assertion_message = ""
        else:
            assertion_message = ""

        print("\nTEST_DETAIL_MARKER:" + assertion_message)
        assert exit_code == 0 and stdout.strip(), assertion_message

    def test_ova_virtualbox_specific(self, config: BaseTesterConfig):
        """Test VirtualBox-specific features."""
        connection = get_connection()

        # Check for VirtualBox Guest Additions
        exit_code, stdout, stderr = connection.execute_command(
            "lsmod | grep -i vbox"
        )

        vbox_guest_detected = exit_code == 0 and stdout.strip()

        # Alternative check for VirtualBox Guest Additions
        exit_code2, stdout2, stderr2 = connection.execute_command(
            "ls -la /opt/VBoxGuestAdditions* 2>/dev/null || ls -la /usr/lib/virtualbox-guest-* 2>/dev/null"
        )

        guest_additions_files = exit_code2 == 0 and stdout2.strip()

        # Combine results
        if vbox_guest_detected or guest_additions_files:
            assertion_message = "VirtualBox Guest Additions appear to be installed"
            if vbox_guest_detected:
                assertion_message += f"\nVirtualBox kernel modules:\n{stdout.strip()}"
            if guest_additions_files:
                assertion_message += f"\nVirtualBox Guest Additions files:\n{stdout2.strip()}"
        else:
            assertion_message = "VirtualBox Guest Additions do not appear to be installed"
            # This might be acceptable depending on your use case, so we'll just warn
            pytest.xfail(assertion_message)

        print("\nTEST_DETAIL_MARKER:" + assertion_message)
        assert vbox_guest_detected or guest_additions_files, assertion_message
