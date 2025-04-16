"""
Factory for creating appropriate connection strategies.
"""

from typing import Optional

from ..config import AMITesterConfig
from ..utils.logger import get_logger
from .base import ConnectionStrategy
from .local import LocalStrategy
from .ssh import SSHStrategy
from .ansible import AnsibleStrategy
from .ami import AMIStrategy

logger = get_logger(__name__)


class StrategyFactory:
    """Factory for creating connection strategies."""

    @staticmethod
    def create_strategy(config: AMITesterConfig) -> Optional[ConnectionStrategy]:
        """Create the appropriate strategy based on configuration.

        Args:
            config: Tester configuration

        Returns:
            Connection strategy instance or None if no valid strategy found
        """
        if config.use_local:
            logger.info("Using local strategy")
            return LocalStrategy(config)

        if config.ami_id:
            logger.info(f"Using AMI strategy for AMI {config.ami_id}")
            return AMIStrategy(config)

        if config.ansible_inventory_path:
            logger.info(f"Using Ansible strategy with inventory {config.ansible_inventory_path}")
            return AnsibleStrategy(config)

        if config.ssh_host:
            logger.info(f"Using SSH strategy for host {config.ssh_host}")
            return SSHStrategy(config)

        logger.error("No valid connection strategy could be determined from configuration")
        return None
