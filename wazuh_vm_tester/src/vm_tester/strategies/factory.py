"""
Factory for creating appropriate connection strategies.
"""


from ..config import AMITesterConfig, BaseTesterConfig, OVATesterConfig
from ..utils.logger import get_logger
from .ami import AMIStrategy
from .ansible import AnsibleStrategy
from .base import ConnectionStrategy
from .local import LocalStrategy
from .ova import OVAStrategy
from .ssh import SSHStrategy

logger = get_logger(__name__)


class StrategyFactory:
    """Factory for creating connection strategies."""

    @staticmethod
    def create_strategy(config: BaseTesterConfig) -> ConnectionStrategy | None:
        """Create the appropriate strategy based on configuration.

        Args:
            config: Tester configuration

        Returns:
            Connection strategy instance or None if no valid strategy found
        """
        if config.use_local:
            logger.info("Using local strategy")
            return LocalStrategy(config)

        # Check if this is an OVA test configuration
        if isinstance(config, OVATesterConfig) and hasattr(config, "ova_s3_path"):
            logger.info(f"Using OVA strategy for OVA at {config.ova_s3_path}")
            return OVAStrategy(config)

        # Check if this is an AMI test configuration
        if isinstance(config, AMITesterConfig) and hasattr(config, "ami_id") and config.ami_id:
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
