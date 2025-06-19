"""
Ansible-based connection implementation.
"""

import os
from typing import Optional, Tuple

from ..utils.logger import get_logger
from ..utils.utils import get_host_connection_info
from .base import ConnectionInterface
from .ssh import SSHConnection

logger = get_logger(__name__)


class AnsibleConnection(ConnectionInterface):
    """Class to handle connections via Ansible inventory."""

    def __init__(
        self,
        inventory_path: str,
        host_id: Optional[str] = None,
        connection_id: Optional[str] = None
    ):
        """Initialize with Ansible inventory info.

        Args:
            inventory_path: Path to Ansible inventory file
            host_id: Host ID in inventory (uses first host if None)
            connection_id: Unique identifier for this connection
        """
        self._inventory_path = inventory_path
        self._host_id = host_id
        self._connection_info = None
        self._ssh_connection = None
        self._is_local = False

        if connection_id:
            self._id = connection_id
        else:
            if host_id:
                self._id = f"ansible-{host_id}"
            else:
                base_name = os.path.basename(inventory_path)
                self._id = f"ansible-{base_name}"

    @property
    def id(self) -> str:
        """Get connection identifier."""
        return self._id

    @property
    def host(self) -> Optional[str]:
        """Get the host address."""
        if self._connection_info:
            return self._connection_info.get('hostname')
        return None

    def connect(self, **kwargs) -> 'AnsibleConnection':
        """Connect to host specified in Ansible inventory.

        Args:
            **kwargs: Additional connection parameters

        Returns:
            Self for method chaining

        Raises:
            ValueError: If inventory file doesn't exist or host not found
        """
        logger.info(f"Connecting to host from Ansible inventory: {self._inventory_path}")

        self._connection_info = get_host_connection_info(
            self._inventory_path,
            self._host_id
        )

        # Check if this is a local connection
        hostname = self._connection_info.get('hostname', '')
        if hostname in ['localhost', '127.0.0.1']:
            logger.info("Detected local connection from Ansible inventory")
            self._is_local = True
            return self

        # Otherwise, create SSH connection
        self._ssh_connection = SSHConnection(
            connection_id=self.id,
            host=self._connection_info['hostname'],
            username=self._connection_info['username'],
            port=self._connection_info.get('port', 22),
            key_path=self._connection_info.get('ssh_key_file'),
        )

        # Connect via SSH
        ssh_common_args = self._connection_info.get('ssh_common_args', '')
        self._ssh_connection.connect(ssh_common_args=ssh_common_args, **kwargs)

        logger.info(f"Connected to {self._connection_info['hostname']} via Ansible inventory")
        return self

    def execute_command(self, command: str, sudo: bool = True) -> Tuple[int, str, str]:
        """Execute a command on the target host.

        Args:
            command: Command to execute
            sudo: Whether to execute with sudo

        Returns:
            Tuple with (exit code, stdout, stderr)
        """
        # For local connections
        if self._is_local:
            import shlex
            import subprocess

            if sudo and not command.startswith("sudo "):
                command = f"sudo {command}"

            logger.debug(f"Executing local command: {command}")

            try:
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
                logger.error(f"Error executing local command: {e}")
                return 1, "", str(e)

        # For SSH connections
        if self._ssh_connection:
            return self._ssh_connection.execute_command(command, sudo)

        # If no connection method available
        raise ValueError("No valid connection method available")

    def close(self) -> None:
        """Close the connection."""
        if self._ssh_connection:
            self._ssh_connection.close()
            logger.info(f"Closed connection to {self.host} from Ansible inventory")
