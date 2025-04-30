"""
SSH connection strategy implementation.
"""

import time
import os
import tempfile
import traceback
from typing import Optional, Tuple

from ..utils.logger import get_logger
from ..connections.base import ConnectionInterface
from ..connections.ssh import SSHConnection
from .base import ConnectionStrategy
from ..aws.ec2 import EC2Client
from ..aws.credentials import AWSRole

logger = get_logger(__name__)


class SSHStrategy(ConnectionStrategy):
    """Strategy for direct SSH connection."""

    def _create_and_associate_temp_key(self, host_ip: str, region: str) -> Tuple[bool, Optional[str]]:
        """Creates a temporary key pair and associates it with the instance based on its IP address.

        Args:
            host_ip: Instance IP address
            region: AWS Region

        Returns:
            Tuple containing (success, path_to_key_file)
        """
        try:
            aws_role = AWSRole(self.config.aws_role)
            ec2_client = EC2Client(region=region, role_type=aws_role)

            temp_key_name = f"wazuh-vm-test-temp-{int(time.time())}"
            logger.info(f"Creating temporary key pair: {temp_key_name}")

            response = ec2_client.ec2.create_key_pair(KeyName=temp_key_name)

            if 'KeyMaterial' not in response:
                logger.error("Failed to get private key material")
                return False, None

            temp_dir = tempfile.mkdtemp()
            key_path = os.path.join(temp_dir, f"{temp_key_name}.pem")

            with open(key_path, 'w') as f:
                f.write(response['KeyMaterial'])

            os.chmod(key_path, 0o400)

            instances_response = ec2_client.ec2.describe_instances(
                Filters=[
                    {'Name': 'ip-address', 'Values': [host_ip]}
                ]
            )

            instance_id = None
            for reservation in instances_response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    break
                if instance_id:
                    break

            if not instance_id:
                logger.error(f"Could not find EC2 instance with IP {host_ip}")
                return False, None

            self._temp_key_name = temp_key_name
            self._temp_key_path = key_path
            self._instance_id = instance_id

            logger.info(f"Successfully created temporary key pair and saved to {key_path}")
            return True, key_path

        except Exception as e:
            logger.error(f"Error creating temporary key pair: {e}")
            return False, None

    def create_connection(self) -> Optional[ConnectionInterface]:
        """Create an SSH connection."""
        if not self.config.ssh_host:
            logger.error("SSH host not specified in configuration")
            return None

        logger.info(f"Creating SSH connection to {self.config.ssh_host}")

        key_path = self.config.ssh_key_path
        password = self.config.ssh_password

        if not key_path and not password and not self.config.ssh_private_key:
            logger.info("No key provided, creating a new temporary key pair for this connection")
            success, temp_key_path = self._create_and_associate_temp_key(
                host_ip=self.config.ssh_host,
                region=self.config.aws_region
            )

            if success:
                key_path = temp_key_path
            else:
                logger.error("Failed to create and associate a temporary key pair")
                return None

        try:
            connection = SSHConnection(
                connection_id="direct-ssh",
                host=self.config.ssh_host,
                username=self.config.ssh_username,
                password=self.config.ssh_password,
                port=self.config.ssh_port,
                key_path=key_path,
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
        if hasattr(self, '_temp_key_name') and self._temp_key_name:
            try:
                aws_role = AWSRole(self.config.aws_role)
                ec2_client = EC2Client(region=self.config.aws_region, role_type=aws_role)
                logger.info(f"Deleting temporary key pair: {self._temp_key_name}")
                ec2_client.ec2.delete_key_pair(KeyName=self._temp_key_name)

                if hasattr(self, '_temp_key_path') and os.path.exists(self._temp_key_path):
                    os.unlink(self._temp_key_path)
                    logger.info(f"Deleted temporary key file: {self._temp_key_path}")
            except Exception as e:
                logger.error(f"Error cleaning up temporary key pair: {e}")

        logger.info("Cleanup for SSH connection completed")
