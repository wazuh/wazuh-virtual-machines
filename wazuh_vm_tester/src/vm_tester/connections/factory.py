"""
Factory module for creating appropriate connections.
"""

from typing import Optional

from ..config import AMITesterConfig
from ..utils.logger import get_logger
from .base import ConnectionInterface
from .local import LocalConnection
from .ssh import SSHConnection
from .ansible import AnsibleConnection

logger = get_logger(__name__)


def create_connection(config: AMITesterConfig) -> Optional[ConnectionInterface]:
    """Create the appropriate connection type based on configuration.

    Args:
        config: Tester configuration

    Returns:
        A connection instance or None if creation fails
    """
    logger.info("Creating connection based on configuration...")

    # Local testing mode
    if config.use_local:
        logger.info("Using local connection for testing")
        return LocalConnection()

    # From Ansible inventory
    if config.ansible_inventory_path:
        logger.info(f"Creating connection from Ansible inventory: {config.ansible_inventory_path}")
        return AnsibleConnection(
            inventory_path=config.ansible_inventory_path,
            host_id=config.ansible_host_id
        )

    # Direct SSH connection
    if config.ssh_host:
        logger.info(f"Creating SSH connection to {config.ssh_host}")
        connection = SSHConnection(
            connection_id="direct-ssh",
            host=config.ssh_host,
            username=config.ssh_username,
            port=config.ssh_port,
            key_path=config.ssh_key_path,
            private_key=config.ssh_private_key
        )

        try:
            connection.connect(
                timeout=config.ssh_connect_timeout,
                max_retries=config.max_retries,
                retry_delay=config.retry_delay
            )
            return connection
        except Exception as e:
            logger.error(f"Failed to establish SSH connection: {e}")
            return None

    logger.error("No valid connection configuration provided")
    return None
