"""
Tests specific to OVA validation.
"""

import os
import pytest

from ..config import BaseTesterConfig, TestType
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

    def test_boot_files(self, config: BaseTesterConfig):
        """Test the existence of required boot files."""
        connection = get_connection()


        files_to_check = [
            "/boot/grub2/wazuh.png",
            "/boot/grub2/grub.cfg",
            "/etc/default/grub"
        ]

        existing_files = []
        missing_files = []

        for file_path in files_to_check:
            check_result = f"File: {file_path}"
            exit_code, stdout, _ = connection.execute_command(
                f"test -f {file_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
            )

            if stdout.strip() == "EXISTS":
                check_result += " exists"
                existing_files.append(check_result)
            else:
                check_result += " does NOT exist"
                missing_files.append(check_result)

        message = "Boot files check results:\n\n"

        if existing_files:
            message += "Existing files:\n- " + "\n- ".join(existing_files) + "\n\n"

        if missing_files:
            message += "Missing files:\n- " + "\n- ".join(missing_files) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if missing_files:
            assert False, "One or more required boot files do not exist. " + message
        else:
            assert True, "All required boot files exist. " + message

    def test_fips_enabled(self, config: BaseTesterConfig):
        """Test that FIPS is correctly enabled."""
        connection = get_connection()

        fips_file = "/proc/sys/crypto/fips_enabled"
        check_result = f"FIPS status file: {fips_file}"


        exit_code, stdout, _ = connection.execute_command(
            f"test -f {fips_file} && echo 'EXISTS' || echo 'NOT_EXISTS'"
        )

        if stdout.strip() != "EXISTS":
            message = f"{check_result} does NOT exist"
            print("\nTEST_DETAIL_MARKER:" + message)
            assert False, message


        exit_code, stdout, _ = connection.execute_command(
            f"cat {fips_file}"
        )

        fips_enabled = stdout.strip() == "1"

        if fips_enabled:
            message = "FIPS is enabled"
        else:
            message = "FIPS is NOT enabled"

        print("\nTEST_DETAIL_MARKER:" + message)
        assert fips_enabled, message

    def test_wazuh_banner(self, config: BaseTesterConfig):
        """Test the existence of the Wazuh banner"""
        connection = get_connection()

        banner_path = "/usr/lib/motd.d/40-wazuh-banner"
        banner_dir = "/usr/lib/motd.d/"


        exit_code, stdout, _ = connection.execute_command(
            f"test -f {banner_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
        )

        banner_exists = stdout.strip() == "EXISTS"


        exit_code, stdout, _ = connection.execute_command(
            f"ls -la {banner_dir} | grep -v '^d' | grep -v 'total' | wc -l"
        )

        file_count = int(stdout.strip())

        is_only_file = file_count == 1

        message = ""
        if banner_exists:
            message += f"Wazuh banner exists at {banner_path}\n"
        else:
            message += f"Wazuh banner does NOT exist at {banner_path}\n"

        if is_only_file:
            message += "It is the only file in the directory"
        else:
            message += f"There are {file_count} files in the directory (should be 1)"

        print("\nTEST_DETAIL_MARKER:" + message)

        assert banner_exists and is_only_file, message

    def test_residual_files(self, config: BaseTesterConfig):
        """Test for residual installation files that should be present."""
        connection = get_connection()

        residual_files = [
            "/etc/systemd/system/wazuh-starter.service",
            "/usr/local/bin/wazuh-starter.sh",
            "/etc/systemd/system/wazuh-starter.timer"
        ]

        existing_files = []
        missing_files = []

        for file_path in residual_files:
            check_result = f"Residual file: {file_path}"
            exit_code, stdout, _ = connection.execute_command(
                f"test -e {file_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
            )

            if stdout.strip() == "EXISTS":
                check_result += " exists"
                existing_files.append(check_result)
            else:
                check_result += " does NOT exist"
                missing_files.append(check_result)

        message = "Residual installation files check results:\n\n"

        if existing_files:
            message += "Existing files:\n- " + "\n- ".join(existing_files) + "\n\n"

        if missing_files:
            message += "Missing files:\n- " + "\n- ".join(missing_files) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if missing_files:
            assert False, "One or more residual installation files do not exist. " + message
        else:
            assert True, "All residual installation files exist. " + message

    def test_dns_resolution(self, config: BaseTesterConfig):
        """Test that DNS resolution is working correctly."""
        connection = get_connection()

        resolv_file = "/etc/resolv.conf"
        test_domain = "google.com"


        exit_code, stdout, _ = connection.execute_command(
            f"test -f {resolv_file} && echo 'EXISTS' || echo 'NOT_EXISTS'"
        )

        resolv_exists = stdout.strip() == "EXISTS"


        exit_code, stdout, stderr = connection.execute_command(
            f"ping -c 1 {test_domain}"
        )

        dns_works = exit_code == 0

        message = ""
        if resolv_exists:
            message += f"The {resolv_file} file exists\n"
        else:
            message += f"The {resolv_file} file does NOT exist\n"

        if dns_works:
            message += f"DNS resolution for {test_domain} works"
        else:
            message += f"DNS resolution for {test_domain} does NOT work\n"
            message += f"Error: {stderr}"

        print("\nTEST_DETAIL_MARKER:" + message)

        assert resolv_exists and dns_works, message
