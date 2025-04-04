from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

import paramiko

from configurer.ami.ami_post_configurer.create_service_directory import create_directory_structure, generate_yaml
from generic import exec_command, modify_file, remote_connection
from models import Inventory
from utils import CertificatesComponent, Logger, RemoteDirectories

logger = Logger("AmiPostCustomizer")


@dataclass
class AmiPostCustomizer:
    inventory: Inventory
    environment_name: str = "certs-env"
    enviroment_python_version: str = "3.11"
    custom_env_dependencies: ClassVar[list[str]] = [
        "pydantic",
        "pyyaml",
        "paramiko",
    ]
    custom_dir_name: str = "wazuh-ami-certs-customize"
    custom_dir_base_path: str = "/etc"
    systemd_services_path = Path("/etc/systemd/system/")
    
    @remote_connection
    def post_customize(self, client: paramiko.SSHClient | None = None) -> None:
        if client is None:
            raise Exception("SSH client is not connected")

        self.create_custom_dir(client=client)
        self.create_certs_env(client=client)
        self.stop_wazuh_server(client=client)
        self.stop_indexer(client=client)
        self.stop_dashboard(client=client)
        self.change_ssh_port_to_default(client=client)
    
    def create_custom_dir(self, client: paramiko.SSHClient) -> None:
        script_dir = Path(__file__).resolve().parent / "templates"
        context = {
            "remote_certs_path": RemoteDirectories.CERTS,
            "certs_tool": CertificatesComponent.CERTS_TOOL,
            "certs_config": CertificatesComponent.CONFIG,
        }
        directory_template = generate_yaml(
            context=context,
            template_dir=str(script_dir),
            template_file="ami_custom_service_directory.j2",
        )
        
        create_directory_structure(base_path=self.custom_dir_base_path, directory_template=directory_template, remote_user=self.inventory.ansible_user, client=client)  # type: ignore
        
    def create_certs_env(self, client: paramiko.SSHClient) -> None:
        logger.debug("Creating custom environment")

        command = f"""
        sudo dnf install -y python{self.enviroment_python_version}
        sudo python{self.enviroment_python_version} -m venv {self.custom_dir_base_path}/{self.custom_dir_name}/{self.environment_name}
        sudo {self.custom_dir_base_path}/{self.custom_dir_name}/{self.environment_name}/bin/pip install --upgrade pip
        sudo {self.custom_dir_base_path}/{self.custom_dir_name}/{self.environment_name}/bin/pip install {' '.join(self.custom_env_dependencies)}
        """
        
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error creating the custom environment")
            raise RuntimeError(f"Error creating the custom environment: {error_output}")
        logger.info_success("Custom environment created successfully")
    
    def stop_service(self, service_name: str, client: paramiko.SSHClient) -> None:
        """
        Stop a systemd service.
        
        Args:
            service_name (str): The name of the service to stop.
        """
        logger.debug(f"Stopping {service_name} service")

        command = f"sudo systemctl stop {service_name}"
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error(f"Error stopping {service_name} service")
            raise RuntimeError(f"Error stopping {service_name} service: {error_output}")
        
    def stop_wazuh_server(self, client: paramiko.SSHClient) -> None:
        """
        Stop the Wazuh server service.
        """
        self.stop_service("wazuh-server", client=client)
        logger.info_success("Wazuh server service stopped successfully")
    
    def remove_indexer_index_list(self, client: paramiko.SSHClient) -> None:
        """
        Remove the indexer index list.
        """

        logger.debug("Removing indexer index list")

        index_list: list[str] = [
            "wazuh-alerts",
            "wazuh-archives",
            "wazuh-states-vulnerabilities",
            "wazuh-statistics",
            "wazuh-monitoring",
        ]
        base_url = "https://localhost:9200"
        commands = []
        for index in index_list:
            commands.append(f"curl -s -o /dev/null -w \"%{{http_code}}\" -X DELETE -u \"admin:admin\" -k \"{base_url}/{index}-*\"")
        
        command = " && ".join(commands)
        command = f"sudo {command}"
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error removing indexer index list")
            raise RuntimeError(f"Error removing indexer index list: {error_output}")
        
        logger.debug("Indexer index list removed successfully")
        
    def run_security_init_script(self, client: paramiko.SSHClient) -> None:
        """
        Run the indexer security init script.
        """
        logger.debug("Running indexer security init script")

        command = "sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh"
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error running indexer security init script")
            raise RuntimeError(f"Error running indexer security init script: {error_output}")
        
        logger.debug("Indexer security init script executed successfully")

    def stop_indexer(self, client: paramiko.SSHClient) -> None:
        """
        Stop the Wazuh indexer service. Before stopping, it removes the indexer index list and runs the security init script.
        """

        self.remove_indexer_index_list(client=client)
        self.run_security_init_script(client=client)
        self.stop_service("wazuh-indexer", client=client)
        logger.info_success("Wazuh indexer service stopped successfully")
        
    def stop_dashboard(self, client: paramiko.SSHClient) -> None:
        """
        Stop and disable the Wazuh dashboard service.
        """
        
        self.stop_service("wazuh-dashboard", client=client)
        command = "sudo systemctl disable wazuh-dashboard"
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error disabling Wazuh dashboard service")
            raise RuntimeError(f"Error disabling Wazuh dashboard service: {error_output}")

        logger.info_success("Wazuh dashboard service stopped successfully")
        
    def change_ssh_port_to_default(self, client: paramiko.SSHClient) -> None:
        """
        Change the SSH port to the default port (22).
        """
        
        logger.debug("Changing SSH port to default (22)")
        replacements = [
            (r"Port \d+", "#Port 22"),
        ]
        modify_file(
            filepath=Path("/etc/ssh/sshd_config"),
            replacements=replacements,
            client=client,
        )
        command = "sudo systemctl restart sshd.service"
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error restarting SSH service")
            raise RuntimeError(f"Error restarting SSH service: {error_output}")
        
        logger.info_success("SSH port changed to default successfully")
        
    