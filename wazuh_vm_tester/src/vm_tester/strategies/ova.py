"""
OVA connection strategy implementation with allocator and S3 OVA support.
"""

import os
import subprocess
import tempfile
import time
import traceback

import yaml

from ..config import OVATesterConfig
from ..connections.base import ConnectionInterface
from ..connections.ssh import SSHConnection
from ..utils.logger import get_logger
from ..utils.utils import digital_clock, download_s3_file, run_scp_command, run_with_progress
from .base import ConnectionStrategy

logger = get_logger(__name__)


class OVAConnection(SSHConnection):
    """Simple connection class for OVA VMs that extends the standard SSHConnection."""

    def __init__(
        self,
        host_ip: str,
        username: str = "wazuh-user",
        port: int = 2201,
        key_path: str | None = None,
        private_key: str | None = None,
        password: str | None = None,
        connection_id: str = "ova-connection",
    ):
        """Initialize the OVA connection.

        Args:
            host_ip: Host IP to connect to (allocator's public IP)
            username: Username for SSH connection
            port: Port for SSH connection (forwarded port)
            key_path: Path to SSH key file
            private_key: SSH private key content
            password: Password for SSH authentication
            connection_id: Unique identifier for this connection
        """
        super().__init__(
            connection_id=connection_id,
            host=host_ip,
            username=username,
            port=port,
            key_path=key_path,
            private_key=private_key,
            password=password,
        )
        logger.info(f"Created OVA connection to {host_ip}:{port} as {username}")


class OVAStrategy(ConnectionStrategy):
    """Strategy for OVA testing."""

    def __init__(self, config: OVATesterConfig):
        """Initialize strategy with configuration.

        Args:
            config: Tester configuration
        """
        super().__init__(config)
        self.config = config
        self.instance_id = None
        self.instance_public_ip = None
        self.allocator_instance = None
        self.allocator_connection = None
        self.ova_vm_ip = None
        self.connection = None
        self.ec2_client = None
        self.allocator_path = os.path.join(tempfile.mkdtemp(), "allocator")
        self.ova_local_path = None
        self.vm_name = f"wazuh-ova-test-{int(time.time())}"
        self.allocator_inventory = {}
        self.vm_ssh_key_path = None
        self.vm_inventory_path = None
        self.ssh_username = None
        self.ssh_port = None
        self.ssh_key_path = None
        self.ova_ssh_port = 2201

    def setup_allocator_instance(self) -> bool:
        """Set up an EC2 instance for OVA allocation using wazuh-automation allocator.

        Returns:
            True if setup was successful, False otherwise
        """
        if not self.config.allocator_enabled:
            logger.info("Allocator is disabled, skipping allocator instance setup")
            return True

        try:
            os.makedirs(self.allocator_path, exist_ok=True)

            wazuh_automation_path = os.environ.get("WAZUH_AUTOMATION_PATH", "./wazuh-automation")
            if not os.path.exists(wazuh_automation_path):
                logger.info("Cloning wazuh-automation repository")
                token = os.environ.get("WAZUH_AUTOMATION_TOKEN")
                cmd = ""
                if token:
                    cmd = f"git clone https://wazuh:{token}@github.com/wazuh/wazuh-automation.git"
                else:
                    cmd = "git clone https://github.com/wazuh/wazuh-automation.git"

                subprocess.run(cmd, shell=True, check=True)

            logger.info("Installing requirements")
            requirements_path = os.path.join(wazuh_automation_path, "deployability/deps/requirements.txt")
            if os.path.exists(requirements_path):
                subprocess.run(f"pip3 install -r {requirements_path}", shell=True, check=True)
            else:
                subprocess.run("pip3 install boto3 pyyaml ansible", shell=True, check=True)

            track_output = os.path.join(self.allocator_path, "track.yml")
            self.vm_inventory_path = os.path.join(self.allocator_path, "inventory.yml")

            instance_name = f"gha_{os.environ.get('GITHUB_RUN_ID', str(int(time.time())))}_ova_test"
            composite_name = "amazon-2023-amd64"

            allocator_cmd = [
                "python3",
                f"{wazuh_automation_path}/deployability/modules/allocation/main.py",
                "--action",
                "create",
                "--provider",
                "aws",
                "--size",
                self.config.allocator_instance_type,
                "--composite-name",
                composite_name,
                "--working-dir",
                self.allocator_path,
                "--track-output",
                track_output,
                "--inventory-output",
                self.vm_inventory_path,
                "--instance-name",
                instance_name,
                "--label-team",
                "devops",
                "--label-termination-date",
                "1d",
            ]

            logger.info(f"Running allocator with command: {' '.join(allocator_cmd)}")
            result = subprocess.run(allocator_cmd, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"Allocator execution failed: {result.stderr}")
                return False

            logger.info(f"Allocator execution succeeded: {result.stdout}")

            self.read_allocator_inventory()

            logger.info(f"Creating SSH connection to allocator instance at {self.instance_public_ip}")
            self.allocator_connection = SSHConnection(
                connection_id=f"ova-allocator-{composite_name}",
                host=self.instance_public_ip,
                username=self.ssh_username,
                port=self.ssh_port,
                key_path=self.ssh_key_path,
            )

            self.allocator_connection.connect()

            logger.info("Allocator instance setup completed successfully")
            return True

        except Exception as e:
            logger.error(f"Error in setup_allocator_instance: {str(e)}")
            logger.error(f"Error in setup_allocator_instance: {traceback.print_exc()}")
            raise Exception(f"Allocator setup failed: {str(e)}")

    def read_allocator_inventory(self) -> bool:
        """Read the inventory file generated by the allocator and extract connection details.

        Returns:
            True if successful, False otherwise
        """
        try:
            if not os.path.exists(self.vm_inventory_path):
                logger.error(f"Inventory file not found at {self.vm_inventory_path}")
                return False

            with open(self.vm_inventory_path) as f:
                self.allocator_inventory = yaml.safe_load(f)

            hosts = self.allocator_inventory.get("all", {}).get("hosts", {})
            if not hosts:
                logger.error("No hosts found in allocator inventory")
                return False

            host_details = next(iter(hosts.values()))
            self.instance_public_ip = host_details.get("ansible_host")
            self.ssh_port = host_details.get("ansible_port", 22)
            self.ssh_key_path = host_details.get("ansible_ssh_private_key_file")
            self.ssh_username = host_details.get("ansible_user")

            logger.info(
                f"Extracted connection details: host={self.instance_public_ip}, user={self.ssh_username}, port={self.ssh_port}"
            )
            return True

        except Exception as e:
            logger.error(f"Error reading allocator inventory: {str(e)}")
            logger.error(f"Error reading allocator inventory: {traceback.format_exc()}")
            raise Exception(f"Failed to read allocator inventory: {str(e)}")

    def install_dependencies(self) -> bool:
        """Install dependencies required for OVA import.

        Returns:
            True if installation was successful, False otherwise
        """
        if not self.allocator_connection:
            logger.error("No allocator connection available")
            return False

        try:
            self.allocator_connection.execute_command(
                "which git || sudo yum update && sudo yum install -y nc git python3 python3-pip && sudo pip3 install hatch"
            )

            logger.info("Cloning wazuh-virtual-machines repository")
            token = os.environ.get("WAZUH_AUTOMATION_TOKEN")
            cmd = ""
            if token:
                cmd = f"git clone https://wazuh:{token}@github.com/wazuh/wazuh-virtual-machines.git"
            else:
                cmd = "git clone https://github.com/wazuh/wazuh-virtual-machines.git"

            subprocess.run(cmd, shell=True, check=True)

            self.allocator_connection.execute_command(
                f"rm -rf /tmp/wazuh-virtual-machines && {cmd} /tmp/wazuh-virtual-machines && cd /tmp/wazuh-virtual-machines && git checkout enhancement/181-ova-tests"
            )

            logger.info("Installing module dependencies...")
            command = """cd /tmp/wazuh-virtual-machines &&
                        sudo hatch run dev-ova-dependencies:install """

            exit_code, stdout, stderr = run_with_progress(
                lambda: self.allocator_connection.execute_command(command, False),
                duration_seconds=120,
                operation_name="Dependencies Installation",
            )

            if exit_code != 0:
                logger.error(f"Dependencies installation failed: {stderr}")
                logger.error(f"Installation output: {stdout}")
                raise Exception(f"Dependencies installation failed with exit code {exit_code}: {stderr}")
            else:
                logger.info(f"exit_code {exit_code}, stdout {stdout}, stderr {stderr}")

            exit_code, stdout, stderr = self.allocator_connection.execute_command("VBoxManage --version")
            if exit_code != 0:
                logger.error("VirtualBox installation verification failed")
                return False

            logger.info(f"VirtualBox version installed: {stdout.strip()}")
            logger.info("VirtualBox and dependencies installed successfully")
            return True

        except Exception as e:
            logger.error(f"Error installing dependencies: {str(e)}")
            logger.error(f"Error installing dependencies: {traceback.print_exc()}")
            raise Exception(f"Failed to install dependencies: {str(e)}")

    def download_ova_from_s3(self) -> bool:
        """Download OVA file from S3 locally and then copy to the allocator instance.

        Returns:
            True if download was successful, False otherwise
        """
        if not self.allocator_connection:
            logger.error("No allocator connection available")
            return False

        if not self.config.ova_s3_path:
            logger.error("No OVA S3 path specified")
            return False

        try:
            if not self.config.ova_s3_path.startswith("s3://"):
                logger.error("S3 path must start with s3://")
                return False

            s3_path = self.config.ova_s3_path[5:]
            bucket_name = s3_path.split("/")[0]
            key = "/".join(s3_path.split("/")[1:])
            ova_filename = os.path.basename(key)

            logger.info(f"Downloading OVA from S3: {self.config.ova_s3_path}")

            local_temp_dir = os.path.join(tempfile.mkdtemp(), "ova_download")
            os.makedirs(local_temp_dir, exist_ok=True)
            local_ova_path = os.path.join(local_temp_dir, ova_filename)

            logger.info(f"Downloading OVA to local path: {local_ova_path}")

            success = run_with_progress(
                download_s3_file,
                args=(bucket_name, key, local_ova_path),
                duration_seconds=30,
                operation_name="S3 Download",
            )

            if not success or not os.path.exists(local_ova_path):
                logger.error("S3 download failed")
                return False

            remote_dir = "/tmp/ova_downloads"
            self.allocator_connection.execute_command(f"mkdir -p {remote_dir}", False)
            self.ova_local_path = f"{remote_dir}/{ova_filename}"

            logger.info(f"Copying OVA to allocator instance at {self.ova_local_path}")

            scp_cmd = [
                "sudo",
                "scp",
                "-P",
                str(self.ssh_port),
                "-i",
                self.ssh_key_path,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                local_ova_path,
                f"{self.ssh_username}@{self.instance_public_ip}:{self.ova_local_path}",
            ]

            logger.info(f"Starting SCP transfer to {self.ova_local_path}")

            success = run_with_progress(
                run_scp_command, args=(scp_cmd,), duration_seconds=60, operation_name="SCP Transfer"
            )

            if not success:
                logger.error("SCP transfer failed")
                raise

            logger.info(f"OVA successfully copied to allocator instance at {self.ova_local_path}")

            return True

        except Exception as e:
            logger.error(f"Error in download_ova_from_s3: {str(e)}")
            logger.error(f"Error in download_ova_from_s3: {traceback.format_exc()}")
            raise Exception(f"Failed to download OVA from S3: {str(e)}")

    def import_ova(self) -> bool:
        """Import the OVA file to VirtualBox and configure it.

        Returns:
            True if import was successful, False otherwise
        """
        if not self.allocator_connection:
            logger.error("No allocator connection available")
            return False

        if not self.ova_local_path:
            logger.error("No OVA local path available")
            return False

        try:
            logger.info(f"Importing OVA from {self.ova_local_path}")

            exit_code, stdout, stderr = self.allocator_connection.execute_command("which VBoxManage")
            if exit_code != 0:
                logger.error("VirtualBox is not installed on the allocator instance")
                return False

            exit_code, stdout, stderr = self.allocator_connection.execute_command(
                f"VBoxManage list vms | grep -q \"{self.vm_name}\" && echo 'exists' || echo 'not-exists'"
            )
            if "exists" in stdout:
                logger.info(f"VM {self.vm_name} already exists, removing it")
                self.allocator_connection.execute_command(f"VBoxManage controlvm {self.vm_name} poweroff || true")
                digital_clock(5)
                self.allocator_connection.execute_command(f"VBoxManage unregistervm {self.vm_name} --delete || true")
                digital_clock(5)

            logger.info("Importing OVA file...")
            exit_code, stdout, stderr = self.allocator_connection.execute_command(
                f"VBoxManage import {self.ova_local_path} --vsys 0 --vmname {self.vm_name}"
            )

            if exit_code != 0:
                logger.error(f"Failed to import OVA: {stderr}")
                return False

            logger.info("Configuring VM resources...")
            self.allocator_connection.execute_command(
                f"VBoxManage modifyvm {self.vm_name} --memory {self.config.vm_memory} --cpus {self.config.vm_cpus}"
            )

            logger.info("Configuring network...")
            self.allocator_connection.execute_command(
                f"VBoxManage modifyvm {self.vm_name} --nic1 {self.config.vm_network_mode}"
            )

            logger.info("Starting the VM...")
            exit_code, stdout, stderr = self.allocator_connection.execute_command(
                f"VBoxManage startvm {self.vm_name} --type headless"
            )

            if exit_code != 0:
                logger.error(f"Failed to start VM: {stderr}")
                return False

            logger.info("Waiting for VM to boot (30 seconds)...")
            digital_clock(30)

            exit_code, stdout, stderr = self.allocator_connection.execute_command(
                f"VBoxManage list runningvms | grep -q \"{self.vm_name}\" && echo 'running' || echo 'not-running'"
            )

            if "running" in stdout:
                logger.info(f"VM {self.vm_name} is running successfully")
                return True
            else:
                logger.error(f"VM {self.vm_name} is not running after waiting")
                return False

        except Exception as e:
            logger.error(f"Error importing OVA: {str(e)}")
            logger.error(f"Trace: {traceback.print_exc()}")
            raise Exception(f"Error importing OVA: {str(e)}")

    def port_forward(self) -> bool:
        """Set up port forwarding between allocator instance and OVA VM.

        Returns:
            True if setup was successful, False otherwise
        """
        if not self.allocator_connection or not self.vm_name:
            logger.error("No allocator connection or VM name available")
            return False

        try:
            logger.info(f"Setting up port forwarding for VM {self.vm_name}")

            logger.info("Shutdown VM...")
            exit_code, stdout, stderr = self.allocator_connection.execute_command(
                f"VBoxManage controlvm {self.vm_name} shutdown"
            )

            if exit_code != 0:
                logger.error(f"Failed to shutdown VM: {stderr}")
                return False

            digital_clock(10)

            logger.info(f"Setting up SSH port forwarding (22 -> {self.ova_ssh_port})")
            exit_code, stdout, stderr = self.allocator_connection.execute_command(
                f'VBoxManage modifyvm "{self.vm_name}" --natpf1 "ssh_ova,tcp,,{self.ova_ssh_port},,22"'
            )

            if exit_code != 0:
                logger.error(f"Failed to set up SSH port forwarding: {stderr}")
                raise Exception(f"Failed to set up SSH port forwarding: {stderr}")

            for port, host_port in self.config.vm_port_forwards.items():
                logger.info(f"Setting up port forwarding for port {port} -> {host_port}")
                exit_code, stdout, stderr = self.allocator_connection.execute_command(
                    f'VBoxManage modifyvm "{self.vm_name}" --natpf1 "{port},tcp,,{host_port},,{port}"'
                )

                if exit_code != 0:
                    logger.warning(f"Failed to set up port forwarding for port {port}: {stderr}")

            logger.info("Starting the VM...")
            exit_code, stdout, stderr = self.allocator_connection.execute_command(
                f"VBoxManage startvm {self.vm_name} --type headless"
            )

            if exit_code != 0:
                logger.error(f"Failed to start VM: {stderr}")
                return False

            logger.info("Waiting for VM to boot (30 seconds)...")
            digital_clock(30)

            logger.info("Verifying SSH port forwarding...")
            max_attempts = 10
            attempt = 0
            success = False

            while attempt < max_attempts and not success:
                attempt += 1
                logger.info(f"Checking SSH port forwarding (attempt {attempt}/{max_attempts})")

                exit_code, stdout, stderr = self.allocator_connection.execute_command(
                    f"nc -z -w5 localhost {self.ova_ssh_port} && echo 'success' || echo 'failed'"
                )

                if "success" in stdout:
                    logger.info("SSH port forwarding is working")
                    success = True
                else:
                    logger.info("SSH port forwarding not ready yet, waiting 10 seconds...")
                    digital_clock(5)

            if not success:
                logger.error("Could not verify SSH port forwarding after multiple attempts")
                return False

            logger.info("Port forwarding set up successfully")
            return True

        except Exception as e:
            logger.error(f"Error setting up port forwarding: {str(e)}")
            logger.error(f"Trace: {traceback.format_exc()}")
            raise Exception(f"Error setting up port forwarding: {str(e)}")

    def create_connection(self) -> ConnectionInterface | None:
        """Create a connection to the OVA VM.

        Returns:
            SSH connection to the OVA VM or None if connection fails
        """

        if self.config.ssh_host:
            logger.info(f"Using direct SSH connection to {self.config.ssh_host}")
            try:
                connection = OVAConnection(
                    connection_id="direct-ova-ssh",
                    host_ip=self.config.ssh_host,
                    username=self.config.ssh_username,
                    port=self.config.ssh_port,
                    password=self.config.ssh_password or "wazuh",
                )

                connection.connect(
                    timeout=self.config.ssh_connect_timeout,
                    max_retries=self.config.max_retries,
                    retry_delay=self.config.retry_delay,
                )

                logger.info("Successfully connected to OVA VM via direct SSH")
                self.connection = connection
                return connection

            except Exception as e:
                logger.error(f"Failed to connect to OVA VM via direct SSH: {str(e)}")
                return None

        logger.info("Starting OVA test process")

        try:
            if not self.setup_allocator_instance():
                logger.error("Failed to set up allocator instance")

            if not self.install_dependencies():
                logger.error("Failed to install dependencies")

            if not self.download_ova_from_s3():
                logger.error("Failed to download OVA from S3")

            if not self.import_ova():
                logger.error("Failed to import OVA")

            if not self.port_forward():
                logger.error("Failed to set up port forwarding")

            try:
                logger.info(f"Creating connection to OVA VM at {self.instance_public_ip}:{self.ova_ssh_port}")

                logger.info("Attempting connection with password authentication")
                ova_connection = OVAConnection(
                    connection_id=f"ova-{self.vm_name}",
                    host_ip=self.instance_public_ip,
                    username=self.config.vm_username or "wazuh-user",
                    port=self.ova_ssh_port,
                    password=self.config.vm_password or "wazuh",
                )

                ova_connection.connect(
                    timeout=self.config.ssh_connect_timeout,
                    max_retries=self.config.max_retries,
                    retry_delay=self.config.retry_delay,
                )

                exit_code, stdout, stderr = ova_connection.execute_command("whoami")
                if exit_code != 0:
                    logger.error(f"Failed to execute test command on OVA VM: {stderr}")
                    return None

                logger.info(f"Successfully connected to OVA VM as user: {stdout.strip()}")
                self.connection = ova_connection
                return ova_connection

            except Exception as e:
                logger.error(f"Failed to connect to OVA VM via password: {str(e)}")
                logger.error(f"Trace: {traceback.format_exc()}")
                raise Exception(f"Failed to connect to OVA VM: {str(e)}")

        except Exception as e:
            logger.error(f"Error in OVA testing process: {str(e)}")
            self.cleanup()
            raise Exception(f"OVA testing process failed: {str(e)}")

    def cleanup(self) -> None:
        """Clean up resources after testing."""

        if self.config.terminate_on_completion:
            try:
                logger.info("Terminating allocator instance")

                wazuh_automation_path = os.environ.get("WAZUH_AUTOMATION_PATH", "./wazuh-automation")
                track_file = os.path.join(self.allocator_path, "track.yml")

                if os.path.exists(track_file):
                    delete_cmd = f"python3 {wazuh_automation_path}/deployability/modules/allocation/main.py --action delete --track-output {track_file}"
                    logger.info(f"Running command: {delete_cmd}")

                    result = subprocess.run(delete_cmd, shell=True, capture_output=True, text=True)

                    if result.returncode != 0:
                        logger.error(f"Allocator deletion failed: {result.stderr}")
                    else:
                        logger.info("Allocator instance terminated successfully")
                else:
                    logger.warning(f"Track file not found at {track_file}, cannot terminate allocator instance")
            except Exception as e:
                logger.error(f"Error terminating allocator instance: {str(e)}")
