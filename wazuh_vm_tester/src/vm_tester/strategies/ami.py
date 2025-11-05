"""
AMI (EC2 instance) connection strategy implementation.
"""

import os
import tempfile
import time

from ..aws.credentials import AWSRole
from ..aws.ec2 import EC2Client
from ..config import AMITesterConfig
from ..connections.base import ConnectionInterface
from ..connections.ssh import SSHConnection
from ..utils.logger import get_logger
from ..utils.utils import digital_clock
from .base import ConnectionStrategy

logger = get_logger(__name__)


class AMIStrategy(ConnectionStrategy):
    """Strategy for testing an AMI by launching EC2 instance."""

    def __init__(self, config: AMITesterConfig):
        """Initialize strategy with configuration.

        Args:
            config: Tester configuration
        """
        super().__init__(config)
        self.instance_id = None
        self.instance_public_ip = None
        self.temp_key_name = None
        self.temp_key_path = None
        self.ec2_client = None
        self.connection = None

    def _generate_ssh_key_pair(self) -> tuple[str, str]:
        """Generate a temporary SSH key pair and import it to AWS.

        Returns:
            Tuple containing (key_name, key_path)
        """
        # Create temporary directory for SSH key
        temp_dir = tempfile.mkdtemp()
        key_path = os.path.join(temp_dir, "wazuh_temp_key")

        # Generate SSH key pair
        os.system(f"ssh-keygen -t rsa -b 2048 -f {key_path} -N '' -q")

        # Key name
        key_name = f"wazuh-vm-test-temp-{int(time.time())}"

        try:
            if not self.ec2_client:
                aws_role = AWSRole(self.config.aws_role)
                self.ec2_client = EC2Client(region=self.config.aws_region, role_type=aws_role)

            with open(f"{key_path}.pub") as f:
                public_key = f.read()

            self.ec2_client.ec2.import_key_pair(KeyName=key_name, PublicKeyMaterial=public_key.encode())
            logger.info(f"Imported temporary SSH key {key_name} to AWS")
        except Exception as e:
            logger.error(f"Error importing SSH key to AWS: {e}")
            raise

        return key_name, key_path

    def create_connection(self) -> ConnectionInterface | None:
        """Launch an EC2 instance from AMI and create connection.

        Returns:
            SSH connection to the launched instance or None if launch fails
        """
        if not self.config.ami_id:
            logger.error("AMI ID not specified in configuration")
            return None

        if not self.ec2_client:
            aws_role = AWSRole(self.config.aws_role)
            self.ec2_client = EC2Client(region=self.config.aws_region, role_type=aws_role)

        if not self.config.ssh_key_path and not self.config.ssh_private_key:
            logger.info("Generating temporary SSH key pair for EC2 instance")
            self.temp_key_name, self.temp_key_path = self._generate_ssh_key_pair()
            key_name = self.temp_key_name
            key_path = self.temp_key_path
        else:
            key_name = self.config.temp_key_name
            key_path = self.config.ssh_key_path

        tags = {
            "Name": f"wazuh-vm-test-{self.config.ami_id}",
            "CreatedBy": "wazuh-vm-tester",
            "AutoTerminate": "true" if self.config.terminate_on_completion else "false",
        }

        if hasattr(self.config, "tags") and self.config.tags:
            tags.update(self.config.tags)

        security_groups = self.config.security_group_ids or self.config.default_security_group_ids
        logger.info(f"Launching EC2 instance from AMI {self.config.ami_id} with security groups {security_groups}")

        # Launch the instance
        try:
            instance = self.ec2_client.launch_instance(
                ami_id=self.config.ami_id,
                instance_type=self.config.instance_type,
                security_group_ids=security_groups,
                tags=tags,
                instance_profile=self.config.instance_profile,
                key_name=key_name,
                wait=True,
                wait_timeout=self.config.launch_timeout,
            )

            if not instance:
                logger.error(f"Failed to launch instance from AMI {self.config.ami_id}")
                return None

            self.instance_id = instance.instance_id
            self.instance_public_ip = instance.public_ip

            if not self.instance_public_ip:
                logger.error(f"Launched instance {self.instance_id} has no public IP address")
                self.cleanup()
                return None

            logger.info(f"Instance {self.instance_id} launched successfully (IP: {self.instance_public_ip})")

            # Wait for services to start
            wait_time = 360
            logger.info(f"Waiting {wait_time} seconds for services to start...")
            digital_clock(wait_time)

            self.connection = SSHConnection(
                connection_id=f"ami-{self.instance_id}",
                host=self.instance_public_ip,
                username=self.config.ssh_username,
                port=self.config.ssh_port,
                key_path=key_path,
                private_key=self.config.ssh_private_key,
            )

            # Connect to the instance
            try:
                self.connection.connect(
                    timeout=self.config.ssh_connect_timeout,
                    max_retries=self.config.max_retries,
                    retry_delay=self.config.retry_delay,
                )

                # Test connection with basic command
                exit_code, stdout, stderr = self.connection.execute_command("whoami")

                if exit_code != 0:
                    logger.error(f"SSH connection test to instance {self.instance_id} failed: {stderr}")
                    self.cleanup()
                    return None

                logger.info(f"Successfully connected to launched instance {self.instance_id}")
                return self.connection

            except Exception as e:
                logger.error(f"Failed to connect to instance {self.instance_id}: {str(e)}")
                self.cleanup()
                return None

        except Exception as e:
            logger.error(f"Error launching instance from AMI {self.config.ami_id}: {str(e)}")
            self.cleanup()
            return None

    def cleanup(self) -> None:
        """Clean up resources after testing."""
        # Close connection if open
        if self.connection:
            try:
                self.connection.close()
                logger.info(f"Closed SSH connection to instance {self.instance_id}")
            except Exception as e:
                logger.warning(f"Error closing SSH connection: {str(e)}")

        # Terminate instance if needed
        if self.instance_id and self.config.terminate_on_completion and self.ec2_client:
            try:
                logger.info(f"Terminating instance {self.instance_id}")
                self.ec2_client.terminate_instance(instance_id=self.instance_id, wait=True)
                logger.info(f"Instance {self.instance_id} terminated successfully")
            except Exception as e:
                logger.error(f"Error terminating instance {self.instance_id}: {str(e)}")

        # Delete temporary key pair if created
        if self.temp_key_name and self.ec2_client:
            try:
                logger.info(f"Deleting temporary key pair {self.temp_key_name}")
                self.ec2_client.ec2.delete_key_pair(KeyName=self.temp_key_name)
                logger.info(f"Temporary key pair {self.temp_key_name} deleted successfully")
            except Exception as e:
                logger.error(f"Error deleting temporary key pair: {str(e)}")
