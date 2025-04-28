"""
OVA connection strategy implementation with allocator and S3 OVA support.
"""

import os
import sys
import time
import tempfile
import shutil
import traceback
import yaml
import boto3
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

from ..config import OVATesterConfig, TestType
from ..utils.logger import get_logger
from ..connections.base import ConnectionInterface
from ..connections.ssh import SSHConnection
from .base import ConnectionStrategy
from ..aws.ec2 import EC2Client
from ..aws.credentials import AWSRole
from ..utils.inventory import digital_clock

logger = get_logger(__name__)


class OVAStrategy(ConnectionStrategy):
    """Strategy for OVA testing."""

    def __init__(self, config: OVATesterConfig):
        """Initialize strategy with configuration.

        Args:
            config: Tester configuration
        """
        super().__init__(config)
        self.config = config  # Typing hint to recognize as OVATesterConfig
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

    def setup_allocator_instance(self) -> bool:
        """Set up an EC2 instance for OVA allocation using wazuh-automation allocator.

        Returns:
            True if setup was successful, False otherwise
        """
        if not self.config.allocator_enabled:
            logger.info("Allocator is disabled, skipping allocator instance setup")
            return True

        try:
            # Create allocator directory
            os.makedirs(self.allocator_path, exist_ok=True)

            # Clone wazuh-automation repository
            wazuh_automation_path = os.environ.get('WAZUH_AUTOMATION_PATH', './wazuh-automation')
            if not os.path.exists(wazuh_automation_path):
                logger.info(f"Cloning wazuh-automation repository")
                subprocess.run("git clone https://github.com/wazuh/wazuh-automation.git", shell=True, check=True)

            # Install requirements
            logger.info("Installing requirements")
            requirements_path = os.path.join(wazuh_automation_path, "deployability/deps/requirements.txt")
            if os.path.exists(requirements_path):
                subprocess.run(f"pip3 install -r {requirements_path}", shell=True, check=True)
            else:
                # Install minimal required packages
                subprocess.run("pip3 install boto3 pyyaml ansible", shell=True, check=True)

            # Set up paths for allocator outputs
            track_output = os.path.join(self.allocator_path, "track.yml")
            self.vm_inventory_path = os.path.join(self.allocator_path, "inventory.yml")

            # Prepare allocator command
            instance_name = f"gha_{os.environ.get('GITHUB_RUN_ID', str(int(time.time())))}_ova_test"
            composite_name = f"linux-amazon-2023-amd64"

            allocator_cmd = [
                "python3", f"{wazuh_automation_path}/deployability/modules/allocation/main.py",
                "--action", "create",
                "--provider", "aws",
                "--size", self.config.allocator_instance_type,
                "--composite-name", composite_name,
                "--working-dir", self.allocator_path,
                "--track-output", track_output,
                "--inventory-output", self.vm_inventory_path,
                "--instance-name", instance_name,
                "--label-team", "devops",
                "--label-termination-date", "1d"
            ]

            # Execute the allocator
            logger.info(f"Running allocator with command: {' '.join(allocator_cmd)}")
            result = subprocess.run(allocator_cmd, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"Allocator execution failed: {result.stderr}")
                return False

            logger.info(f"Allocator execution succeeded: {result.stdout}")

            # Read the inventory file to get connection information
            self.read_allocator_inventory()

            # Create SSH connection to the allocator instance
            logger.info(f"Creating SSH connection to allocator instance at {self.instance_public_ip}")
            self.allocator_connection = SSHConnection(
                connection_id=f"ova-allocator-{composite_name}",
                host=self.instance_public_ip,
                username=self.ssh_username,
                port=self.ssh_port,
                key_path=self.ssh_key_path
            )

            # Connect to the instance
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

            with open(self.vm_inventory_path, 'r') as f:
                self.allocator_inventory = yaml.safe_load(f)

            hosts = self.allocator_inventory.get('all', {}).get('hosts', {})
            if not hosts:
                logger.error("No hosts found in allocator inventory")
                return False

            host_details = next(iter(hosts.values()))
            self.instance_public_ip = host_details.get('ansible_host')
            self.ssh_port = host_details.get('ansible_port', 22)
            self.ssh_key_path = host_details.get('ansible_ssh_private_key_file')
            self.ssh_username = host_details.get('ansible_user')

            logger.info(f"Extracted connection details: host={self.instance_public_ip}, user={self.ssh_username}, port={self.ssh_port}")
            return True

        except Exception as e:
            logger.error(f"Error reading allocator inventory: {str(e)}")
            logger.error(f"Error reading allocator inventory: {traceback.print_exc()}")
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
            # Install git and other prerequisites if needed
            self.allocator_connection.execute_command("which git || sudo yum update && sudo yum install -y nc git python3 python3-pip && sudo pip3 install hatch")

            # Clone the repository directly on the remote machine
            logger.info("Cloning wazuh-virtual-machines repository")
            self.allocator_connection.execute_command("rm -rf /tmp/wazuh-virtual-machines && git clone https://github.com/wazuh/wazuh-virtual-machines.git /tmp/wazuh-virtual-machines && git checkout enhancement/181-ova-tests")

            # Install required Python dependencies and run the dependencies installer script
            logger.info("Installing module dependencies...")
            command = """cd /tmp/wazuh-virtual-machines &&
                        hatch run dev-ova-dependencies:install """

            exit_code, stdout, stderr = self.allocator_connection.execute_command(command)

            if exit_code != 0:
                logger.error(f"Dependencies installation failed: {stderr}")
                logger.error(f"Installation output: {stdout}")
                raise Exception(f"Dependencies installation failed with exit code {stderr}")
            else:
                logger.info(f"exit_code {exit_code}, stdout {stdout}, stderr {stderr}")

            # Verify VirtualBox installation
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
            # Parse S3 path
            if not self.config.ova_s3_path.startswith('s3://'):
                logger.error("S3 path must start with s3://")
                return False

            s3_path = self.config.ova_s3_path[5:]  # Remove s3:// prefix
            bucket_name = s3_path.split('/')[0]
            key = '/'.join(s3_path.split('/')[1:])
            ova_filename = os.path.basename(key)

            logger.info(f"Downloading OVA from S3: {self.config.ova_s3_path}")

            # Create local temp directory for download
            local_temp_dir = os.path.join(tempfile.mkdtemp(), "ova_download")
            os.makedirs(local_temp_dir, exist_ok=True)
            local_ova_path = os.path.join(local_temp_dir, ova_filename)

            # Download the OVA file locally using boto3
            logger.info(f"Downloading OVA to local path: {local_ova_path}")
            s3_client = boto3.client('s3')
            try:
                s3_client.download_file(bucket_name, key, local_ova_path)
                logger.info(f"OVA file downloaded locally to {local_ova_path}")
            except Exception as e:
                logger.error(f"Failed to download OVA from S3: {str(e)}")
                return False

            # Create remote directory on allocator instance
            remote_dir = "/tmp/ova_downloads"
            self.allocator_connection.execute_command(f"mkdir -p {remote_dir}")
            self.ova_local_path = f"{remote_dir}/{ova_filename}"

            # Copy OVA to allocator instance using SCP
            logger.info(f"Copying OVA to allocator instance at {self.ova_local_path}")

            # Build SCP command
            scp_cmd = [
                "scp",
                "-P", str(self.ssh_port),
                "-i", self.ssh_key_path,
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                local_ova_path,
                f"{self.ssh_username}@{self.instance_public_ip}:{self.ova_local_path}"
            ]

            logger.info(f"Running SCP command: {' '.join(scp_cmd)}")
            result = subprocess.run(scp_cmd, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"Failed to copy OVA to allocator instance: {result.stderr}")
                return False

            logger.info(f"OVA successfully copied to allocator instance at {self.ova_local_path}")

            # Clean up local temporary file
            try:
                os.remove(local_ova_path)
                os.rmdir(local_temp_dir)
                logger.info(f"Removed local temporary OVA file")
            except Exception as e:
                logger.warning(f"Could not remove local temporary files: {str(e)}")

            return True

        except Exception as e:
            logger.error(f"Error in download_ova_from_s3: {str(e)}")
            logger.error(f"Error in download_ova_from_s3: {traceback.print_exc()}")
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

            # Check if VirtualBox is installed
            exit_code, stdout, stderr = self.allocator_connection.execute_command("which VBoxManage")
            if exit_code != 0:
                logger.error("VirtualBox is not installed on the allocator instance")
                return False

            # Check if VM already exists and remove it
            exit_code, stdout, stderr = self.allocator_connection.execute_command(f"VBoxManage list vms | grep -q \"{self.vm_name}\" && echo 'exists' || echo 'not-exists'")
            if "exists" in stdout:
                logger.info(f"VM {self.vm_name} already exists, removing it")
                self.allocator_connection.execute_command(f"VBoxManage controlvm {self.vm_name} poweroff || true")
                time.sleep(5)
                self.allocator_connection.execute_command(f"VBoxManage unregistervm {self.vm_name} --delete || true")
                time.sleep(5)

            # Import OVA
            logger.info("Importing OVA file...")
            exit_code, stdout, stderr = self.allocator_connection.execute_command(
                f"VBoxManage import {self.ova_local_path} --vsys 0 --vmname {self.vm_name}"
            )

            if exit_code != 0:
                logger.error(f"Failed to import OVA: {stderr}")
                return False

            # Configure VM resources
            logger.info("Configuring VM resources...")
            self.allocator_connection.execute_command(
                f"VBoxManage modifyvm {self.vm_name} --memory {self.config.vm_memory} --cpus {self.config.vm_cpus}"
            )

            # Configure network
            logger.info("Configuring network...")
            self.allocator_connection.execute_command(
                f"VBoxManage modifyvm {self.vm_name} --nic1 {self.config.vm_network_mode}"
            )

            # Start the VM
            logger.info("Starting the VM...")
            exit_code, stdout, stderr = self.allocator_connection.execute_command(
                f"VBoxManage startvm {self.vm_name} --type headless"
            )

            if exit_code != 0:
                logger.error(f"Failed to start VM: {stderr}")
                return False

            # Wait for VM to boot
            logger.info("Waiting for VM to boot (60 seconds)...")
            time.sleep(60)

            # Check if VM is running
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

            # Add SSH port forwarding
            logger.info("Setting up SSH port forwarding (2200 -> 2222)")
            exit_code, stdout, stderr = self.allocator_connection.execute_command(
                f'VBoxManage modifyvm "{self.vm_name}" --natpf1 "ssh,tcp,,2222,,2200"'
            )

            if exit_code != 0:
                logger.error(f"Failed to set up SSH port forwarding: {stderr}")
                return False

            # Add custom port forwardings if any
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

            # Wait a moment for port forwarding to take effect
            time.sleep(5)

            # Verify SSH port is accessible
            logger.info("Verifying SSH port forwarding...")
            max_attempts = 10
            attempt = 0
            success = False

            while attempt < max_attempts and not success:
                attempt += 1
                logger.info(f"Checking SSH port forwarding (attempt {attempt}/{max_attempts})")

                exit_code, stdout, stderr = self.allocator_connection.execute_command(
                    "nc -z -w5 localhost 2222 && echo 'success' || echo 'failed'"
                )

                if "success" in stdout:
                    logger.info("SSH port forwarding is working")
                    success = True
                else:
                    logger.info("SSH port forwarding not ready yet, waiting 10 seconds...")
                    time.sleep(10)

            if not success:
                logger.error("Could not verify SSH port forwarding after multiple attempts")
                return False

            logger.info("Port forwarding set up successfully")
            return True

        except Exception as e:
            logger.error(f"Error setting up port forwarding: {str(e)}")
            logger.error(f"Trace: {traceback.print_exc()}")
            raise Exception(f"Error setting up port forwarding: {str(e)}")

    def create_connection(self) -> Optional[ConnectionInterface]:
        """Create a connection to the OVA VM.

        Returns:
            SSH connection to the OVA VM or None if connection fails
        """
        # For direct SSH testing when OVA VM is already running
        if self.config.ssh_host:
            logger.info(f"Using direct SSH connection to {self.config.ssh_host}")
            try:
                connection = SSHConnection(
                    connection_id="direct-ova-ssh",
                    host=self.config.ssh_host,
                    username=self.config.ssh_username,
                    port=self.config.ssh_port,
                    key_path=self.config.ssh_key_path,
                    private_key=self.config.ssh_private_key
                )

                connection.connect(
                    timeout=self.config.ssh_connect_timeout,
                    max_retries=self.config.max_retries,
                    retry_delay=self.config.retry_delay
                )

                logger.info(f"Successfully connected to OVA VM via direct SSH")
                self.connection = connection
                return connection

            except Exception as e:
                logger.error(f"Failed to connect to OVA VM via direct SSH: {str(e)}")
                return None

        # For OVA testing process
        logger.info("Starting OVA test process")

        try:
            # Step 1: Set up allocator instance
            if not self.setup_allocator_instance():
                logger.error("Failed to set up allocator instance")

            # Step 2: Install dependencies on allocator instance
            if not self.install_dependencies():
                logger.error("Failed to install dependencies")

            # Step 3: Download OVA from S3
            if not self.download_ova_from_s3():
                logger.error("Failed to download OVA from S3")

            # Step 4: Import OVA
            if not self.import_ova():
                logger.error("Failed to import OVA")

            # Step 5: Set up port forwarding
            if not self.port_forward():
                logger.error("Failed to set up port forwarding")

            # Step 6: Create SSH connection to OVA through port forwarding
            try:
                logger.info("Connecting to OVA VM via SSH through port forwarding")

                # Create connection to the VM through port forwarding
                connection = SSHConnection(
                    connection_id="ova-vm",
                    host=self.instance_public_ip,
                    username=self.config.vm_username or "wazuh-user",
                    port=2222,
                    key_path=self.config.ssh_key_path,
                    private_key=self.config.ssh_private_key
                )

                # Connect to the OVA VM with retries
                logger.info("Attempting to connect to OVA VM...")
                connection.connect(
                    timeout=self.config.ssh_connect_timeout,
                    max_retries=self.config.max_retries,
                    retry_delay=self.config.retry_delay
                )

                logger.info("Successfully connected to OVA VM")
                self.connection = connection
                return connection

            except Exception as e:
                logger.error(f"Failed to connect to OVA VM: {str(e)}")
                return None
        finally:
            self.cleanup()

    def cleanup(self) -> None:
        """Clean up resources after testing."""

        # Terminate allocator instance if auto-terminate is enabled
        if self.config.terminate_on_completion:
            try:
                # Delete the instance using the allocator module
                logger.info("Terminating allocator instance")

                wazuh_automation_path = os.environ.get('WAZUH_AUTOMATION_PATH', './wazuh-automation')
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
