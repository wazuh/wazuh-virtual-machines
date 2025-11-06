"""
Ansible connection strategy implementation.
"""

import os

from ..connections.ansible import AnsibleConnection
from ..connections.base import ConnectionInterface
from ..utils.logger import get_logger
from .base import ConnectionStrategy

logger = get_logger(__name__)


class AnsibleStrategy(ConnectionStrategy):
    """Strategy for Ansible inventory connection."""

    def create_connection(self) -> ConnectionInterface | None:
        """Create a connection from Ansible inventory.

        Returns:
            Ansible connection instance or None if creation fails
        """
        if not self.config.ansible_inventory_path:
            logger.error("Ansible inventory path not specified in configuration")
            return None

        if not os.path.exists(self.config.ansible_inventory_path):
            logger.error(f"Ansible inventory file not found: {self.config.ansible_inventory_path}")
            return None

        logger.info(f"Creating connection from Ansible inventory: {self.config.ansible_inventory_path}")

        try:
            connection = AnsibleConnection(
                inventory_path=self.config.ansible_inventory_path, host_id=self.config.ansible_host_id
            )

            connection.connect()

            exit_code, stdout, stderr = connection.execute_command("whoami")

            if exit_code != 0:
                logger.error(f"Ansible connection test failed: {stderr}")
                return None

            logger.info("Successfully connected using Ansible inventory")
            return connection

        except Exception as e:
            logger.error(f"Failed to establish connection from Ansible inventory: {str(e)}")
            return None

    def cleanup(self) -> None:
        """Clean up resources after testing."""
        logger.info("Cleanup for Ansible connection (no action needed)")
