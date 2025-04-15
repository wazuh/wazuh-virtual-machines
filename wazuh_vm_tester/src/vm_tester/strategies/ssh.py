"""
SSH connection strategy implementation.
"""

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

    def _get_key_from_aws(self, key_name: str, region: str) -> Tuple[bool, Optional[str]]:
        """Finds and downloads an SSH key from AWS.

        Args:
            key_name: Name of the key pair in AWS
            region: AWS Region

        Returns:
            Tuple containing (success, path_to_key_file)
        """
        try:
            # Inicializar cliente EC2
            aws_role = AWSRole(self.config.aws_role)
            ec2_client = EC2Client(region=region, role_type=aws_role)

            logger.info(f"Looking up key pair '{key_name}' in AWS region {region}")

            # Verificar si la clave existe
            response = ec2_client.ec2.describe_key_pairs(
                KeyNames=[key_name]
            )

            if not response or 'KeyPairs' not in response or not response['KeyPairs']:
                logger.error(f"Key pair '{key_name}' not found in AWS")
                return False, None

            try:
                key_detail = ec2_client.ec2.get_key_pair(
                    KeyPairId=response['KeyPairs'][0]['KeyPairId'],
                    IncludePublicKey=True
                )

                if 'KeyMaterial' in key_detail:
                    temp_dir = tempfile.mkdtemp()
                    key_path = os.path.join(temp_dir, f"{key_name}.pem")

                    with open(key_path, 'w') as f:
                        f.write(key_detail['KeyMaterial'])

                    os.chmod(key_path, 0o400)

                    logger.info(f"Key downloaded and saved to {key_path}")
                    return True, key_path
            except Exception as e:
                logger.warning(f"Could not download key material: {e}")
                pass

            logger.error(
                "The key pair exists in AWS, but the key hardware cannot be downloaded because AWS does not store private keys."
                "You must use --ssh-key-path to provide the private key."
            )
            return False, None

        except Exception as e:
            logger.error(f"Error al intentar obtener la clave de AWS: {e}")
            logger.error(traceback.format_exc())
            return False, None

    def create_connection(self) -> Optional[ConnectionInterface]:
        """Create an SSH connection.

        Returns:
            SSH connection instance or None if connection fails
        """
        if not self.config.ssh_host:
            logger.error("SSH host not specified in configuration")
            return None

        logger.info(f"Creating SSH connection to {self.config.ssh_host}")

        key_path = self.config.ssh_key_path

        if not key_path and self.config.key_name:
            logger.info(f"Trying to use AWS key pair: {self.config.key_name}")
            success, aws_key_path = self._get_key_from_aws(
                key_name=self.config.key_name,
                region=self.config.aws_region
            )

            if success:
                key_path = aws_key_path
            else:
                logger.error("Failed to get key from AWS and no ssh-key-path provided")
                return None

        try:
            connection = SSHConnection(
                connection_id="direct-ssh",
                host=self.config.ssh_host,
                username=self.config.ssh_username,
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
        logger.info("Cleanup for SSH connection (no action needed)")
