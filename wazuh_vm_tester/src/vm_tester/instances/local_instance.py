"""
Local machine instance implementation.
"""

import subprocess
import shlex
from typing import Tuple

from ..config import get_logger
from .base import InstanceInterface

logger = get_logger(__name__)


class LocalInstance(InstanceInterface):
    """Class to handle local machine testing."""

    def __init__(self):
        """Initialize with local machine info."""
        self._instance_id = "local"
        self._region = "local"
        self._public_ip = "127.0.0.1"
        self._private_ip = "127.0.0.1"
        self._connected = False

    @property
    def instance_id(self) -> str:
        """Get the instance ID."""
        return self._instance_id

    @property
    def public_ip(self) -> str:
        """Get the public IP address."""
        return self._public_ip

    @property
    def private_ip(self) -> str:
        """Get the private IP address."""
        return self._private_ip

    @property
    def region(self) -> str:
        """Get the region."""
        return self._region

    def connect_ssh(self, **kwargs) -> 'LocalInstance':
        """Mock method for local testing (no SSH needed).

        Args:
            **kwargs: Ignored connection parameters

        Returns:
            Self for method chaining
        """
        logger.info("Local testing mode - SSH connection not needed")
        self._connected = True
        return self

    def execute_command(self, command: str, sudo: bool = True) -> Tuple[int, str, str]:
        """Execute a command on the local machine.

        Args:
            command: Command to execute
            sudo: Whether to execute with sudo

        Returns:
            Tuple with (exit code, stdout, stderr)
        """
        if sudo and not command.startswith("sudo "):
            command = f"sudo {command}"

        logger.debug(f"Executing command: {command}")

        try:
            # Execute the command
            process = subprocess.Popen(
                shlex.split(command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            exit_code = process.returncode

            return exit_code, stdout, stderr
        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return 1, "", str(e)

    def close_ssh(self) -> None:
        """Mock method for local testing."""
        logger.info("Local testing mode - no SSH connection to close")
        self._connected = False
