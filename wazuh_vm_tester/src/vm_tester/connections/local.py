"""
Local machine connection implementation.
"""

import subprocess
import shlex
from typing import Tuple

from ..utils.logger import get_logger
from .base import ConnectionInterface

logger = get_logger(__name__)


class LocalConnection(ConnectionInterface):
    """Class to handle local machine connections."""

    def __init__(self, connection_id: str = "local"):
        """Initialize with local machine info.

        Args:
            connection_id: Unique identifier for this connection
        """
        self._id = connection_id
        self._host = "127.0.0.1"
        self._connected = False

    @property
    def id(self) -> str:
        """Get connection identifier."""
        return self._id

    @property
    def host(self) -> str:
        """Get the host address."""
        return self._host

    def connect(self, **kwargs) -> 'LocalConnection':
        """Mock method for local testing (no connection needed).

        Args:
            **kwargs: Ignored connection parameters

        Returns:
            Self for method chaining
        """
        logger.info("Local testing mode - connection not needed")
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

    def close(self) -> None:
        """Mock method for local testing."""
        logger.info("Local testing mode - no connection to close")
        self._connected = False
