"""
EC2 instance implementation using SSHConnection.
"""

from typing import Optional, Tuple

from ..utils.logger import get_logger
from .base import InstanceInterface
from ..connections.ssh import SSHConnection

logger = get_logger(__name__)


class EC2Instance(InstanceInterface):
    """Class for managing an EC2 instance."""

    def __init__(
        self,
        instance_id: str,
        region: str,
        public_ip: Optional[str] = None,
        private_ip: Optional[str] = None,
    ):
        """Initialize with the instance ID.

        Args:
            instance_id: EC2 instance ID
            region: AWS region
            public_ip: Public IP address (optional)
            private_ip: Private IP address (optional)
        """
        self._instance_id = instance_id
        self.region = region
        self._public_ip = public_ip
        self._private_ip = private_ip
        self._ssh_connection = None

    @property
    def instance_id(self) -> str:
        """Get the instance ID."""
        return self._instance_id

    @property
    def public_ip(self) -> Optional[str]:
        """Get the public IP address."""
        return self._public_ip

    @property
    def private_ip(self) -> Optional[str]:
        """Get the private IP address."""
        return self._private_ip

    def connect_ssh(
        self,
        username: str,
        key_path: Optional[str] = None,
        private_key: Optional[str] = None,
        port: int = 22,
        timeout: int = 30,
        ssh_common_args: Optional[str] = None,
        max_retries: int = 5,
        retry_delay: int = 30,
        **kwargs
    ) -> 'EC2Instance':
        """Connect to the instance via SSH with retries.

        Args:
            username: Username for the SSH connection
            key_path: Path to the private key file (optional)
            private_key: Private key content (optional)
            port: SSH port
            timeout: Connection timeout in seconds for each attempt
            ssh_common_args: Additional SSH arguments
            max_retries: Maximum number of connection attempts
            retry_delay: Delay between retries in seconds
            **kwargs: Additional parameters for paramiko

        Returns:
            Self for method chaining

        Raises:
            ValueError: If neither key_path nor private_key is provided
            SSHException: If the SSH connection fails after all retries
        """
        if not self.public_ip:
            raise ValueError("No public IP address available for SSH connection")

        if self._ssh_connection is None:
            self._ssh_connection = SSHConnection(
                connection_id=f"ec2-{self.instance_id}",
                host=self.public_ip,
                username=username,
                port=port,
                key_path=key_path,
                private_key=private_key
            )

        self._ssh_connection.connect(
            timeout=timeout,
            ssh_common_args=ssh_common_args,
            max_retries=max_retries,
            retry_delay=retry_delay,
            **kwargs
        )

        return self

    def execute_command(
        self, command: str, sudo: bool = True
    ) -> Tuple[int, str, str]:
        """Execute a command on the instance via SSH.

        Args:
            command: Command to execute
            sudo: Whether to execute with sudo

        Returns:
            Tuple with (exit code, stdout, stderr)

        Raises:
            ValueError: If no SSH connection is established
        """
        if self._ssh_connection is None:
            raise ValueError("No SSH connection established, call connect_ssh first")

        return self._ssh_connection.execute_command(command, sudo)

    def close_ssh(self) -> None:
        """Close the SSH connection if open."""
        if self._ssh_connection:
            self._ssh_connection.close()
            self._ssh_connection = None
            logger.info(f"SSH connection closed to {self.public_ip}")
