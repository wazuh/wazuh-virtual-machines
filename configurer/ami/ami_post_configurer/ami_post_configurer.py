from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

import paramiko

from configurer.ami.ami_post_configurer.create_service_directory import create_directory_structure, generate_yaml
from generic import exec_command, modify_file, remote_connection
from models import Inventory
from utils import CertificatesComponent, Logger, PasswordToolComponent, RemoteDirectories

logger = Logger("AmiPostConfigurer")


@dataclass
class AmiPostConfigurer:
    inventory: Inventory
    environment_name: str = "customizer-env"
    enviroment_python_version: str = "3.11"
    custom_env_dependencies: ClassVar[list[str]] = [
        "pydantic",
        "pyyaml",
        "paramiko",
    ]
    custom_dir_name: str = "wazuh-ami-customizer"
    custom_dir_base_path: str = "/etc"
    cloud_instances_path: Path = Path("/var/lib/cloud/instances")
    journal_logs_path: Path = Path("/var/log/journal")
    journald__config_file_path: Path = Path("/etc/systemd/journald.conf")
    log_directory_path: Path = Path("/var/log")
    wazuh_indexer_log_path: Path = Path("/var/log/wazuh-indexer")
    wazuh_server_log_path: Path = Path("/var/ossec/logs")
    wazuh_dashboard_log_path: Path = Path("/var/log/wazuh-dashboard")

    @remote_connection
    def post_customize(self, client: paramiko.SSHClient | None = None) -> None:
        """
        Perform post-customization tasks on an AMI instance using an SSH client.

        This method executes a series of operations to prepare the AMI instance
        for deployment. It requires an active SSH client connection to perform
        the tasks remotely.

        Tasks performed:
            - Creation of a custom directory to store the necessary files for the execution
              of the service that will create the custom certs for each instance.
            - Set up python environment located in the custom directory that will be used for the
              certificates creation service.
            - Stop Wazuh server, indexer, and dashboard services.
            - Change SSH port to the default value.
            - Clean up cloud instance files, journal logs, yum cache, and logout files.
            - Enable journal log storage.
            - Remove generated logs, command history, and authorized keys.
            - Clean up the Wazuh configuration directory.

        Args:
            client (paramiko.SSHClient | None): The SSH client used to connect to
                the AMI instance.

        Returns:
            None
        """

        if client is None:
            raise Exception("SSH client is not connected")

        logger.debug_title("AMI post configuration")

        self.create_custom_dir(client=client)
        self.create_certs_env(client=client)
        self.stop_wazuh_server(client=client)
        self.stop_wazuh_indexer(client=client)
        self.stop_wazuh_dashboard(client=client)
        self.change_ssh_port_to_default(client=client)
        self.clean_cloud_instance_files(client=client)
        self.clean_journal_logs(client=client)
        self.clean_yum_cache(client=client)
        self.clean_logout_files(client=client)
        self.enable_journal_log_storage(client=client)
        self.clean_generated_logs(client=client)
        self.clean_history(client=client)
        self.clean_authorized_keys(client=client)
        self.clean_wazuh_configure_directory(client=client)

        logger.info_success("AMI post configuration completed successfully")

    def create_custom_dir(self, client: paramiko.SSHClient) -> None:
        """
        Creates a custom directory structure on a remote machine using a predefined template.

        This method generates a directory structure based on a YAML template file and
        creates it on the remote machine using the provided SSH client.
        Here will be stored the necessary files for the execution of the service that will
        create the custom certs for each instance.

        Args:
            client (paramiko.SSHClient): An active SSH client used to connect to the remote machine.

        Returns:
            None
        """

        script_dir = Path(__file__).resolve().parent / "templates"
        context = {
            "remote_certs_path": RemoteDirectories.CERTS,
            "certs_tool": CertificatesComponent.CERTS_TOOL,
            "certs_config": CertificatesComponent.CONFIG,
            "password_tool_path": RemoteDirectories.PASSWORD_TOOL,
            "password_tool": PasswordToolComponent.PASSWORD_TOOL,
        }
        directory_template = generate_yaml(
            context=context,
            template_dir=str(script_dir),
            template_file="ami_custom_service_directory.j2",
        )

        create_directory_structure(
            base_path=self.custom_dir_base_path,
            directory_template=directory_template,
            remote_user=self.inventory.ansible_user,
            client=client,
        )

    def create_certs_env(self, client: paramiko.SSHClient) -> None:
        """
        Creates a custom Python virtual environment on a remote machine via SSH.

        This method installs the specified Python version, creates a virtual environment,
        upgrades pip, and installs the required dependencies in the virtual environment.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute commands on the remote machine.

        Returns:
            None
        '"""

        logger.debug("Creating custom environment")

        command = f"""
        sudo dnf install -y python{self.enviroment_python_version}
        sudo python{self.enviroment_python_version} -m venv {self.custom_dir_base_path}/{self.custom_dir_name}/{self.environment_name}
        sudo {self.custom_dir_base_path}/{self.custom_dir_name}/{self.environment_name}/bin/pip install --upgrade pip
        sudo {self.custom_dir_base_path}/{self.custom_dir_name}/{self.environment_name}/bin/pip install {" ".join(self.custom_env_dependencies)}
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
            client (paramiko.SSHClient): An active SSH client used to execute commands on the remote machine.

        Returns:
            None
        """

        logger.debug(f"Stopping {service_name} service")

        command = f"sudo systemctl stop {service_name}"
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error(f"Error stopping the {service_name} service")
            raise RuntimeError(f"Error stopping the {service_name} service: {error_output}")

        logger.info_success(f"{service_name} service stopped successfully")

    def stop_wazuh_server(self, client: paramiko.SSHClient) -> None:
        """
        Stop the Wazuh server service.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute commands on the remote machine.

        Returns:
            None
        """

        self.stop_service("wazuh-manager", client=client)

    def remove_wazuh_indexes(self, client: paramiko.SSHClient) -> None:
        """
        Remove all wazuh-* indexes.
        """

        logger.debug("Removing all wazuh- indexes")

        base_url = "https://127.0.0.1:9200"

        command = f'sudo curl -s -o /dev/null -w "%{{http_code}}" -X DELETE -u "admin:admin" -k "{base_url}/wazuh-*"'
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error removing wazuh- indexes")
            raise RuntimeError(f"Error removing wazuh- indexes: {error_output}")

        logger.debug("wazuh- indexes removed successfully")

    def run_security_init_script(self, client: paramiko.SSHClient) -> None:
        """
        Run the indexer security init script.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute commands on the remote machine.

        Returns:
            None
        """

        logger.debug("Running indexer security init script")

        command = "sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh"
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error running the indexer security init script")
            raise RuntimeError(f"Error running the indexer security init script: {error_output}")

        logger.debug("Indexer security init script executed successfully")

    def stop_wazuh_indexer(self, client: paramiko.SSHClient) -> None:
        """
        Stop the Wazuh indexer service. Before stopping, it removes the indexer index list and runs the security init script.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute commands on the remote machine.

        Returns:
            None
        """

        self.remove_wazuh_indexes(client=client)
        self.run_security_init_script(client=client)
        self.stop_service("wazuh-indexer", client=client)

    def stop_wazuh_dashboard(self, client: paramiko.SSHClient) -> None:
        """
        Stop and disable the Wazuh dashboard service and disable it from starting on boot.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute commands on the remote machine.

        Returns:
            None
        """

        self.stop_service("wazuh-dashboard", client=client)

        logger.debug("Disabling wazuh-dashboard service")

        command = "sudo systemctl --quiet disable wazuh-dashboard"
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error disabling the wazuh-dashboard service")
            raise RuntimeError(f"Error disabling the wazuh-dashboard service: {error_output}")

        logger.info_success("wazuh-dashboard service disabled successfully")

    def change_ssh_port_to_default(self, client: paramiko.SSHClient) -> None:
        """
        Change the SSH port to the default port (22).

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute commands on the remote machine.

        Returns:
            None
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
            logger.error("Error restarting the SSH service")
            raise RuntimeError(f"Error restarting the SSH service: {error_output}")

        logger.info_success("SSH port changed to default successfully")

    def clean_cloud_instance_files(self, client: paramiko.SSHClient) -> None:
        """
        Clean up files and directories related to the cloud instance.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute commands on the remote machine.

        Returns:
            None
        """

        logger.debug("Cleaning up cloud instance files")
        command = f"[ -d {self.cloud_instances_path} ] && sudo rm -rf {self.cloud_instances_path}/*"
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error cleaning up cloud instance files")
            raise RuntimeError(f"Error cleaning up cloud instance files: {error_output}")

        logger.info_success("Cloud instance files cleaned up successfully")

    def clean_journal_logs(self, client: paramiko.SSHClient) -> None:
        """
        Clean up journal logs. This method removes all files in the journal logs directory.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute commands on the remote machine.

        Returns:
            None
        """

        logger.debug("Cleaning up journal logs")
        command = f"[ -d {self.journal_logs_path} ] && sudo rm -rf {self.journal_logs_path}/*"
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error cleaning up journal logs")
            raise RuntimeError(f"Error cleaning up journal logs: {error_output}")

        logger.info_success("Journal logs cleaned up successfully")

    def clean_yum_cache(self, client: paramiko.SSHClient) -> None:
        """
        Clean up the yum cache.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute commands on the remote machine.

        Returns:
            None
        """

        logger.debug("Cleaning up yum cache")
        command = "sudo dnf clean all"
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error cleaning up yum cache")
            raise RuntimeError(f"Error cleaning up yum cache: {error_output}")

        logger.info_success("Yum cache cleaned up successfully")

    def clean_logout_files(self, client: paramiko.SSHClient) -> None:
        """
        Clean up logout files from the root and wazuh users.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute commands on the remote machine.

        Returns:
            None
        """

        logger.debug("Cleaning up logout files")
        command = f"""
        echo '' | sudo tee /home/{self.inventory.ansible_user}/.bash_logout > /dev/null
        echo '' | sudo tee /root/.bash_logout > /dev/null
        """
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error cleaning up logout files")
            raise RuntimeError(f"Error cleaning up logout files: {error_output}")

        logger.info_success("Logout files cleaned up successfully")

    def enable_journal_log_storage(self, client: paramiko.SSHClient) -> None:
        """
        Enables journal log storage by modifying the journald configuration file.

        This method updates the journald configuration file to enable log storage
        by replacing specific configuration lines.

        Args:
            client (paramiko.SSHClient): An SSH client instance used to connect to
                the remote system and modify the configuration file.

        Returns:
            None
        """

        logger.debug("Enabling journal log storage")
        replacements = [
            ("Storage=none", "#Storage=auto"),
            ("ForwardToSyslog=yes", "#ForwardToSyslog=yes"),
        ]
        modify_file(
            filepath=self.journald__config_file_path,
            replacements=replacements,
            client=client,
        )

        logger.info_success("Journal log storage enabled successfully")

    def clean_generated_logs(self, client: paramiko.SSHClient) -> None:
        """
        Cleans up generated log files during the configuration in specified directories by truncating their contents.

        This method checks if the specified log directories exist and contain files. If so, it
        truncates the contents of all files within those directories to free up space while
        retaining the file structure.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute commands on a remote server.

        Returns:
            None
        """

        logger.debug(f'Cleaning up generated logs in "{self.log_directory_path}"')

        command = f"""
            if [ -d {self.log_directory_path} ] && sudo find {self.log_directory_path} -type f | read; then
                sudo find {self.log_directory_path} -type f -exec sudo bash -c 'cat /dev/null > "$1"' _ {{}} \\;
            fi
            if [ -d {self.wazuh_indexer_log_path} ] && sudo find {self.wazuh_indexer_log_path} -type f | read; then
                sudo find {self.wazuh_indexer_log_path} -type f -exec sudo bash -c 'cat /dev/null > "$1"' _ {{}} \\;
            fi
            if [ -d {self.wazuh_server_log_path} ] && sudo find {self.wazuh_server_log_path} -type f | read; then
                sudo find {self.wazuh_server_log_path} -type f -exec sudo bash -c 'cat /dev/null > "$1"' _ {{}} \\;
            fi
            if [ -d {self.wazuh_dashboard_log_path} ] && sudo find {self.wazuh_dashboard_log_path} -type f | read; then
                sudo find {self.wazuh_dashboard_log_path} -type f -exec sudo bash -c 'cat /dev/null > "$1"' _ {{}} \\;
            fi
        """

        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error cleaning up generated logs")
            raise RuntimeError(f"Error cleaning up generated logs: {error_output}")

        logger.info_success("Generated logs cleaned up successfully")

    def clean_history(self, client: paramiko.SSHClient) -> None:
        """
        Cleans up the bash history files for both the root user and the wazuh user.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute commands on the
                                         remote machine.
        Returns:
            None
        """

        logger.debug("Cleaning up history files")

        command = f"""
            echo '' | sudo tee /home/{self.inventory.ansible_user}/.bash_history > /dev/null
            echo '' | sudo tee /root/.bash_history > /dev/null
        """
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error cleaning up history files")
            raise RuntimeError(f"Error cleaning up history files: {error_output}")

        logger.info_success("History files cleaned up successfully")

    def clean_authorized_keys(self, client: paramiko.SSHClient) -> None:
        """
        Cleans up the authorized_keys files for both the wazuh user and the root user.

        This method removes all existing SSH authorized keys by overwriting their
        `authorized_keys` files with empty content.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute the cleanup commands
                                         on the remote machine.

        Returns:
            None
        """

        logger.debug("Cleaning up authorized keys")

        command = f"""
            echo '' | sudo tee /home/{self.inventory.ansible_user}/.ssh/authorized_keys > /dev/null
            echo '' | sudo tee /root/.ssh/authorized_keys > /dev/null
        """
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error cleaning up authorized keys")
            raise RuntimeError(f"Error cleaning up authorized keys: {error_output}")

        logger.info_success("Authorized keys cleaned up successfully")

    def clean_wazuh_configure_directory(self, client: paramiko.SSHClient) -> None:
        """
        Cleans up the Wazuh configuration directory that was created during the provision process.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute the
                cleanup command on the remote machine.

        Returns:
            None
        """

        logger.debug("Cleaning up Wazuh configure directory")

        command = f"sudo rm -rf {RemoteDirectories.WAZUH_ROOT_DIR}"
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error(f"Error cleaning up Wazuh configure directory {RemoteDirectories.WAZUH_ROOT_DIR}")
            raise RuntimeError(
                f"Error cleaning up Wazuh configure directory {RemoteDirectories.WAZUH_ROOT_DIR}: {error_output}"
            )

        logger.info_success("Wazuh configure directory cleaned up successfully")
