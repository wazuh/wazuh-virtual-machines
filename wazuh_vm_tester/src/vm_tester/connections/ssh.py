"""
SSH connection implementation.
"""

import os
import re
import time
import tempfile
import stat
import subprocess
import socket
import threading
import shutil
from io import StringIO
from typing import Optional, Tuple, Union, Any

import paramiko
from paramiko.ssh_exception import SSHException

from ..utils.logger import get_logger
from .base import ConnectionInterface
from ..utils.utils import digital_clock

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
        password: Optional[str] = None,
    ):
        """Initialize SSH connection.

        Args:
            connection_id: Unique identifier for this connection
            host: Host to connect to
            username: SSH username
            port: SSH port
            key_path: Path to private key file
            private_key: Private key content
            password: Password for password-based authentication
        """
        self._id = connection_id
        self._host = host
        self._username = username
        self._port = port
        self._key_path = key_path
        self._private_key = private_key
        self._password = password
        self._ssh_client = None
        self._connection_type = None
        self._temp_dir = None
        self.default_timeout = 240
        self.connect_timeout = 30

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
            ValueError: If neither key_path nor private_key nor password is provided
            SSHException: If the SSH connection fails after all retries
        """
        if not self._key_path and not self._private_key and not self._password:
            raise ValueError("Either key_path, private_key, or password must be provided for SSH connection")

        if self._ssh_client is not None:
            return self


        self.connect_timeout = timeout

        last_exception = None
        attempts = 0

        logger.info(f"Attempting to establish SSH connection to {self._host}:{self._port} (max {max_retries} attempts, timeout {timeout}s per attempt)")

        while attempts < max_retries:
            attempts += 1


            using_password = self._password is not None
            using_key = (self._key_path is not None) or (self._private_key is not None)

            logger.info(f"SSH connection attempt {attempts}/{max_retries} (auth: {'password' if using_password else 'key'}, port: {self._port})")


            if using_key and not using_password:
                try:
                    logger.info("Using standard Paramiko method with key authentication")

                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    connect_options = {
                        "hostname": self._host,
                        "port": self._port,
                        "username": self._username,
                        "timeout": timeout,
                        "allow_agent": False,
                        "look_for_keys": False
                    }


                    if self._key_path:
                        connect_options["key_filename"] = self._key_path
                    elif self._private_key:
                        key = paramiko.RSAKey.from_private_key(self._private_key)
                        connect_options["pkey"] = key


                    if ssh_common_args:
                        port_match = re.search(r"-p\s+(\d+)", ssh_common_args)
                        if port_match:
                            custom_port = int(port_match.group(1))
                            logger.debug(f"Using custom port from SSH common args: {custom_port}")
                            connect_options["port"] = custom_port


                    for key, value in kwargs.items():
                        connect_options[key] = value


                    client.connect(**connect_options)


                    self._connection_type = "paramiko"
                    self._ssh_client = client
                    logger.info(f"SSH connection established to {self._host} using standard Paramiko method with key")
                    return self

                except Exception as e:
                    logger.debug(f"Standard Paramiko connection with key failed: {str(e)}")
                    last_exception = e


            elif using_password:
                try:
                    logger.info("Using direct subprocess method with password authentication")


                    sshpass_path = shutil.which("sshpass")
                    if not sshpass_path:
                        logger.warning("sshpass not installed. Attempting to install it.")
                        try:
                            if os.path.exists("/etc/debian_version"):

                                subprocess.run(["sudo", "apt-get", "update", "-y"], check=True)
                                subprocess.run(["sudo", "apt-get", "install", "-y", "sshpass"], check=True)
                            elif os.path.exists("/etc/redhat-release"):

                                subprocess.run(["sudo", "yum", "install", "-y", "sshpass"], check=True)
                            elif os.path.exists("/etc/arch-release"):

                                subprocess.run(["sudo", "pacman", "-S", "--noconfirm", "sshpass"], check=True)
                            elif os.path.exists("/usr/local/bin/brew"):

                                subprocess.run(["brew", "install", "hudochenkov/sshpass/sshpass"], check=True)
                            else:
                                logger.error("Could not detect package manager to install sshpass")
                                raise SSHException("sshpass not installed and could not be automatically installed")

                            sshpass_path = shutil.which("sshpass")
                            if not sshpass_path:
                                raise SSHException("sshpass installation succeeded but command not found in PATH")
                        except Exception as e:
                            logger.error(f"Failed to install sshpass: {str(e)}")
                            raise SSHException(f"Failed to install sshpass: {str(e)}")


                    ssh_client = SubprocessSSHClient(
                        host=self._host,
                        port=self._port,
                        username=self._username,
                        password=self._password,
                        sshpass_path=sshpass_path,
                        timeout=timeout
                    )


                    self._ssh_client = ssh_client
                    self._connection_type = "subprocess"
                    logger.info(f"SSH connection established to {self._host} using subprocess method with password")
                    return self

                except Exception as e:
                    last_exception = e
                    logger.debug(f"Subprocess SSH method failed: {str(e)}")


            if attempts < max_retries:
                logger.info(f"Waiting {retry_delay} seconds before next attempt...")
                digital_clock(retry_delay)
            else:
                logger.error(f"All {max_retries} SSH connection attempts failed")

        raise SSHException(
            f"Could not establish SSH connection to {self._host} after {max_retries} attempts: {last_exception}"
        )

    def execute_command(
        self,
        command: str,
        sudo: bool = True,
        timeout: Optional[int] = None,
        retry_on_timeout: bool = False,
        max_retries: int = 3,
        timeout_multiplier: float = 2.0
    ) -> Tuple[int, str, str]:
        """Execute a command on the remote host via SSH with support for long-running commands.

        Args:
            command: Command to execute
            sudo: Whether to execute with sudo
            timeout: Command timeout in seconds (None uses default timeout)
            retry_on_timeout: Whether to retry if timeout occurs
            max_retries: Maximum number of retries for timeouts
            timeout_multiplier: Factor to increase timeout on each retry

        Returns:
            Tuple with (exit code, stdout, stderr)

        Raises:
            ValueError: If no SSH connection is established
        """
        if self._ssh_client is None:
            raise ValueError("No SSH connection established, call connect first")

        if sudo and not command.startswith("sudo "):
            command = f"sudo {command}"


        current_timeout = timeout if timeout is not None else self.default_timeout


        attempt = 0
        max_attempts = max_retries + 1 if retry_on_timeout else 1
        accumulated_stdout = ""
        accumulated_stderr = ""
        last_exit_code = None

        logger.debug(f"Executing command: {command}")

        while attempt < max_attempts:
            attempt += 1

            if attempt > 1:
                logger.info(f"Retry attempt {attempt-1}/{max_retries} with timeout {current_timeout}s")

            try:

                stdin, stdout, stderr = self._ssh_client.exec_command(command, timeout=current_timeout)


                exit_code = stdout.channel.recv_exit_status()


                stdout_str = stdout.read()
                stderr_str = stderr.read()


                if isinstance(stdout_str, bytes):
                    stdout_str = stdout_str.decode('utf-8', errors='replace')
                elif not isinstance(stdout_str, str):
                    stdout_str = str(stdout_str)

                if isinstance(stderr_str, bytes):
                    stderr_str = stderr_str.decode('utf-8', errors='replace')
                elif not isinstance(stderr_str, str):
                    stderr_str = str(stderr_str)


                accumulated_stdout += stdout_str
                accumulated_stderr += stderr_str
                last_exit_code = exit_code


                if exit_code != 124 or not retry_on_timeout:
                    if exit_code == 124:
                        logger.warning(f"Command timed out after {current_timeout}s: {command}")
                        accumulated_stderr += f"\nCommand timed out after {current_timeout} seconds."
                    else:
                        logger.debug(f"Command completed with exit code {exit_code}")

                    return (exit_code, accumulated_stdout, accumulated_stderr)


                logger.warning(f"Command timed out after {current_timeout}s, will retry with increased timeout")
                current_timeout = int(current_timeout * timeout_multiplier)

            except Exception as e:
                logger.error(f"Error executing command: {str(e)}")


                accumulated_stderr += f"\nError: {str(e)}"


                if attempt >= max_attempts:
                    return (1 if last_exit_code is None else last_exit_code, accumulated_stdout, accumulated_stderr)


                logger.info(f"Will retry after execution error")


        logger.error(f"Command failed to complete within allowed time after {max_attempts} attempts")
        return (124, accumulated_stdout, accumulated_stderr)

    def close(self) -> None:
        """Close the SSH connection if open."""
        if self._ssh_client:
            try:
                self._ssh_client.close()
            except Exception as e:
                logger.debug(f"Error closing SSH connection: {str(e)}")
            finally:
                self._ssh_client = None
                logger.info(f"SSH connection closed to {self._host}")


        if hasattr(self, '_temp_dir') and self._temp_dir:
            try:
                shutil.rmtree(self._temp_dir)
                logger.debug("Removed temporary directory")
            except Exception as e:
                logger.debug(f"Error removing temporary directory: {str(e)}")


class SubprocessSSHClient:
    """SSH client implementation using subprocess for enhanced timeout handling."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        sshpass_path: str,
        timeout: int = 30
    ):
        """Initialize the subprocess-based SSH client.

        Args:
            host: Remote host to connect to
            port: SSH port
            username: SSH username
            password: SSH password
            sshpass_path: Path to sshpass executable
            timeout: Default timeout in seconds
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.sshpass_path = sshpass_path
        self.timeout = timeout


        self._test_connection()

    def _test_connection(self):
        """Test the SSH connection with a simple command."""
        try:
            stdin, stdout, stderr = self.exec_command("whoami")
            exit_code = stdout.channel.recv_exit_status()

            if exit_code != 0:
                error_msg = stderr.read()
                raise SSHException(f"SSH test connection failed with exit code {exit_code}: {error_msg}")

            username = stdout.read().strip()
            logger.info(f"SSH connection test successful, connected as: {username}")

        except Exception as e:
            logger.error(f"SSH connection test failed: {str(e)}")
            raise

    def exec_command(self, command, get_pty=False, timeout=None):
        """Execute a command remotely and return file-like objects for stdin, stdout, stderr

        Args:
            command: The command to execute
            get_pty: Whether to request a PTY (ignored in this implementation)
            timeout: Command timeout in seconds (if None, uses the default timeout)

        Returns:
            Tuple of (stdin, stdout, stderr) file-like objects
        """

        cmd_timeout = timeout if timeout is not None else self.timeout


        cmd_args = [
            self.sshpass_path, "-p", self.password,
            "ssh",
            "-p", str(self.port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            f"{self.username}@{self.host}",
            command
        ]


        stdout_data = []
        stderr_data = []
        exit_code = None
        exit_code_lock = threading.Lock()
        process = None
        process_lock = threading.Lock()


        collection_active = True


        def read_stdout():
            nonlocal process
            if process is None:
                return

            while collection_active:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    stdout_data.append(line)


        def read_stderr():
            nonlocal process
            if process is None:
                return

            while collection_active:
                line = process.stderr.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    stderr_data.append(line)


        def monitor_process():
            nonlocal process, exit_code, collection_active
            if process is None:
                return


            proc_exit_code = process.wait()


            with exit_code_lock:
                exit_code = proc_exit_code


            collection_active = False


        def handle_timeout():
            nonlocal process, exit_code, collection_active


            start_time = time.time()
            remaining_time = cmd_timeout

            while remaining_time > 0:

                with exit_code_lock:
                    if exit_code is not None:
                        return


                sleep_time = min(0.5, remaining_time)
                time.sleep(sleep_time)


                elapsed = time.time() - start_time
                remaining_time = cmd_timeout - elapsed



            with process_lock:
                if process is not None and process.poll() is None:
                    logger.warning(f"Command timed out after {cmd_timeout} seconds, sending SIGTERM: {command}")
                    try:
                        process.terminate()


                        for _ in range(10):
                            if process.poll() is not None:
                                break
                            time.sleep(0.1)


                        if process.poll() is None:
                            logger.warning(f"Command didn't respond to SIGTERM, sending SIGKILL")
                            process.kill()
                    except Exception as e:
                        logger.error(f"Error terminating command: {str(e)}")


                    with exit_code_lock:
                        exit_code = 124


                    collection_active = False

        try:

            process = subprocess.Popen(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )


            stdout_thread = threading.Thread(target=read_stdout)
            stderr_thread = threading.Thread(target=read_stderr)
            monitor_thread = threading.Thread(target=monitor_process)
            timeout_thread = threading.Thread(target=handle_timeout)

            stdout_thread.daemon = True
            stderr_thread.daemon = True
            monitor_thread.daemon = True
            timeout_thread.daemon = True

            stdout_thread.start()
            stderr_thread.start()
            monitor_thread.start()
            timeout_thread.start()



            monitor_thread.join(cmd_timeout + 5)


            with exit_code_lock:
                final_exit_code = 255 if exit_code is None else exit_code


            collection_active = False


            stdout_thread.join(1)
            stderr_thread.join(1)


            stdin_file = StringIO()
            stdout_file = StringIO("".join(stdout_data))
            stderr_file = StringIO("".join(stderr_data))


            class DummyChannel:
                def __init__(self, exit_code):
                    self.exit_code = exit_code
                def recv_exit_status(self):
                    return self.exit_code

            stdout_file.channel = DummyChannel(final_exit_code)

            return stdin_file, stdout_file, stderr_file

        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")


            stdin_file = StringIO()
            stdout_file = StringIO("")
            stderr_file = StringIO(str(e))

            class DummyChannel:
                def __init__(self, exit_code):
                    self.exit_code = exit_code
                def recv_exit_status(self):
                    return self.exit_code

            stdout_file.channel = DummyChannel(1)

            return stdin_file, stdout_file, stderr_file
