"""
SSH connection strategy implementation.
"""

from typing import Optional

from ..config import get_logger
from ..connections.base import ConnectionInterface
from ..connections.ssh import SSHConnection
from .base import ConnectionStrategy

logger = get_logger(__name__)


class SSHStrategy(ConnectionStrategy):
    """Strategy for direct SSH connection."""

    def create_connection(self) -> Optional[ConnectionInterface]:
        """Create an SSH connection.

        Returns:
            SSH connection instance or None if connection fails
        """
        if not self.config.ssh_host:
            logger.error("SSH host not specified in configuration")
            return None

        logger.info(f"Creating SSH connection to {self.config.ssh_host}")

        try:
            connection = SSHConnection(
                connection_id="direct-ssh",
                host=self.config.ssh_host,
                username=self.config.ssh_username,
                port=self.config.ssh_port,
                key_path=self.config.ssh_key_path,
                private_key=self.config.ssh_private_key
            )

            connection.connect(
                timeout=self.config.ssh_connect_timeout,
                max_retries=self.config.max_retries,
                retry_delay=self.config.retry_delay
            )

            exit_code, stdout, stderr = connection.execute_command("whoami")

            if exit_code != 0:
                logger.error(f"SSH connection test failed: {stderr}")
                return None

            logger.info(f"Successfully connected to {self.config.ssh_host} via SSH")
            return connection

        except Exception as e:
            logger.error(f"Failed to establish SSH connection: {str(e)}")
            return None

    def cleanup(self) -> None:
        """Clean up resources after testing."""
        logger.info("Cleanup for SSH connection (no action needed)")
