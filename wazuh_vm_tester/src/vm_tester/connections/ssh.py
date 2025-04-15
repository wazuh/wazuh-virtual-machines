"""
SSH connection implementation.
"""

import re
import time
from typing import Optional, Tuple

import paramiko
from paramiko.ssh_exception import SSHException
import socket

from ..utils.logger import get_logger
from .base import ConnectionInterface
from ..utils.inventory import digital_clock

logger = get_logger(__name__)


class SSHConnection(ConnectionInterface):
    """Class for SSH connections."""

    def __init__(
        self,
        connection_id: str,
        host: str,
        username: str = "wazuh-user",
        port: int = 22,
        key_path: Optional[str] = None,
        private_key: Optional[str] = None,
    ):
        """Initialize SSH connection.

        Args:
            connection_id: Unique identifier for this connection
            host: Host to connect to
            username: SSH username
            port: SSH port
            key_path: Path to private key file
            private_key: Private key content
        """
        self._id = connection_id
        self._host = host
        self._username = username
        self._port = port
        self._key_path = key_path
        self._private_key = private_key
        self._ssh_client = None

    @property
    def id(self) -> str:
        """Get connection identifier."""
        return self._id

    @property
    def host(self) -> str:
        """Get the host address."""
        return self._host

    def connect(
        self,
        timeout: int = 30,
        ssh_common_args: Optional[str] = None,
        max_retries: int = 5,
        retry_delay: int = 30,
        **kwargs
    ) -> 'SSHConnection':
        """Connect to the remote host via SSH with retries.

        Args:
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
        if not self._key_path and not self._private_key:
            raise ValueError("Either key_path or private_key must be provided for SSH connection")

        if self._ssh_client is not None:
            return self

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_options = {}
        if ssh_common_args:
            # Parse SSH arguments
            if "-o StrictHostKeyChecking=no" in ssh_common_args:
                logger.debug("Setting StrictHostKeyChecking=no")
                connect_options["look_for_keys"] = False
                connect_options["allow_agent"] = False

            port_match = re.search(r"-p\s+(\d+)", ssh_common_args)
            if port_match:
                custom_port = int(port_match.group(1))
                logger.debug(f"Using custom port from SSH common args: {custom_port}")
                self._port = custom_port

        pkey = None
        if self._private_key:
            pkey = paramiko.RSAKey.from_private_key(self._private_key)

        last_exception = None
        attempts = 0

        logger.info(f"Attempting to establish SSH connection to {self._host} (max {max_retries} attempts, timeout {timeout}s per attempt)")

        while attempts < max_retries:
            attempts += 1
            try:
                conn_args = {
                    "hostname": self._host,
                    "username": self._username,
                    "port": self._port,
                    "timeout": timeout,
                    **connect_options,
                    **kwargs
                }

                # Set authentication method
                if self._key_path:
                    conn_args["key_filename"] = self._key_path
                else:
                    conn_args["pkey"] = pkey

                logger.info(f"SSH connection attempt {attempts}/{max_retries}...")
                logger.debug(f"Connection arguments: {conn_args}")
                client.connect(**conn_args)
                self._ssh_client = client
                logger.info(f"SSH connection established to {self._host} on attempt {attempts}")
                return self
            except (SSHException, socket.error, ConnectionError, TimeoutError) as e:
                last_exception = e
                logger.warning(f"SSH connection attempt {attempts} failed: {str(e)}")

                if attempts < max_retries:
                    logger.info(f"Waiting {retry_delay} seconds before next attempt...")
                    digital_clock(retry_delay)
                else:
                    logger.error(f"All {max_retries} SSH connection attempts failed")

        raise SSHException(
            f"Could not establish SSH connection to {self._host} after {max_retries} attempts: {last_exception}"
        )

    def execute_command(
        self, command: str, sudo: bool = True
    ) -> Tuple[int, str, str]:
        """Execute a command on the remote host via SSH.

        Args:
            command: Command to execute
            sudo: Whether to execute with sudo

        Returns:
            Tuple with (exit code, stdout, stderr)

        Raises:
            ValueError: If no SSH connection is established
        """
        if self._ssh_client is None:
            raise ValueError("No SSH connection established, call connect first")

        if sudo and not command.startswith("sudo "):
            command = f"sudo {command}"

        logger.debug(f"Executing command: {command}")
        stdin, stdout, stderr = self._ssh_client.exec_command(command)
        exit_code = stdout.channel.recv_exit_status()

        return (
            exit_code,
            stdout.read().decode("utf-8"),
            stderr.read().decode("utf-8"),
        )

    def close(self) -> None:
        """Close the SSH connection if open."""
        if self._ssh_client:
            self._ssh_client.close()
            self._ssh_client = None
            logger.info(f"SSH connection closed to {self._host}")
