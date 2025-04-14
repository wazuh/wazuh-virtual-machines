"""
Factory module for creating instances.
"""

from typing import Optional

from ..config import AMITesterConfig, get_logger
from .base import InstanceInterface
from .local_instance import LocalInstance
from .ec2_instance import EC2Instance

logger = get_logger(__name__)


def create_instance(config: AMITesterConfig) -> Optional[InstanceInterface]:
    """Create the appropriate instance type based on configuration.

    Args:
        config: Tester configuration

    Returns:
        An instance of EC2Instance, LocalInstance, or None if creation fails
    """
    logger.info("Creating instance based on configuration...")

    # Local testing mode
    if config.use_local:
        logger.info("Using local instance for testing")
        return LocalInstance()

    # For inventory
    if config.ansible_inventory_path and config.ssh_host in ['localhost', '127.0.0.1']:
        logger.info("Using local instance from Ansible inventory")
        return LocalInstance()

    # SSH connection
    if config.ssh_host:
        logger.info(f"Creating instance for direct SSH to {config.ssh_host}")
        return EC2Instance(
            instance_id="direct-ssh",
            region=config.aws_region,
            public_ip=config.ssh_host
        )

    # AMI testing
    if config.ami_id:
        logger.info(f"Launching new EC2 instance from AMI {config.ami_id}")
        from ..aws.ec2 import EC2Client
        ec2_client = EC2Client(region=config.aws_region)

        security_groups = config.security_group_ids or config.default_security_group_ids

        instance = ec2_client.launch_instance(
            ami_id=config.ami_id,
            instance_type=config.instance_type,
            security_group_ids=security_groups,
            tags=config.tags,
            instance_profile=config.instance_profile,
            key_name=config.temp_key_name,
            wait=True,
            wait_timeout=config.launch_timeout,
        )

        if instance:
            logger.info(f"Instance {instance.instance_id} launched successfully")
            return instance
        else:
            logger.error(f"Failed to launch instance from AMI {config.ami_id}")
            return None

    # Existing EC2 instance
    if config.existing_instance_id:
        logger.info(f"Using existing EC2 instance {config.existing_instance_id}")
        from ..aws.ec2 import EC2Client
        ec2_client = EC2Client(region=config.aws_region)
        instance_info = ec2_client.get_instance_info(config.existing_instance_id)

        if instance_info:
            return EC2Instance(
                instance_id=config.existing_instance_id,
                region=config.aws_region,
                public_ip=instance_info.get("PublicIpAddress"),
                private_ip=instance_info.get("PrivateIpAddress"),
            )
        else:
            logger.error(f"Failed to get information for instance {config.existing_instance_id}")
            return None

    logger.error("No valid instance configuration provided")
    return None
