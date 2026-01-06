from dataclasses import dataclass
from pathlib import Path

import paramiko

from generic import exec_command, modify_file, remote_connection
from models import Inventory
from utils import Logger

logger = Logger("AmiPreConfigurer")


@dataclass
class AmiPreConfigurer:
    """
    AmiCustomizer is a class responsible for customizing an Amazon Machine Image (AMI) for Wazuh.
    It provides methods to configure the AMI environment, including user management, hostname updates,
    cloud configuration, and system services.
    """

    inventory: Inventory
    wazuh_banner_path: Path
    local_set_ram_script_path: Path
    local_update_indexer_heap_service_path: Path
    local_customize_certs_service_path: Path
    local_customize_certs_timer_path: Path
    cloud_config_path: Path = Path("/etc/cloud/cloud.cfg")
    ssh_config_path: Path = Path("/etc/ssh/sshd_config")
    instance_update_logo_path: Path = Path("/etc/update-motd.d/70-available-updates")
    motd_scripts_directory = Path("/etc/update-motd.d")
    default_motd_file_path = Path("/usr/lib/motd.d/30-banner")
    journald_file_path = Path("/etc/systemd/journald.conf")
    systemd_services_path = Path("/etc/systemd/system/")
    ram_service_script_destination_path = Path("/etc")
    instance_username: str = "ec2-user"
    wazuh_hostname: str = "wazuh"
    wazuh_user: str = "wazuh-user"
    wazuh_password: str = "wazuh"
    ssh_default_port: int = 22

    @remote_connection
    def customize(self, client: paramiko.SSHClient | None = None) -> None:
        """
        Customizes the Amazon Machine Image (AMI) by performing a series of configuration steps.

        This method ensures that the AMI is properly configured for use with Wazuh by:
        - Removing the default instance user.
        - Configuring the cloud-init configuration file.
        - Updating the hostname.
        - Customizing the Message of the Day (MOTD) logo.
        - Stopping persistent storage of journald logs.
        - Creating a service to set RAM-related configurations.

        Args:
            client (paramiko.SSHClient | None, optional): An optional SSH client instance to execute
                remote commands. If not provided, the method assumes local execution.

        Returns:
            None
        """

        if client is None:
            raise Exception("SSH client is not connected")

        if self.inventory.ansible_user != self.wazuh_user:
            raise Exception(f'Before customizing the AMI, the Wazuh user  "{self.wazuh_user}" must be created')

        self.remove_default_instance_user(client=client)
        self.configure_cloud_cfg(client=client)
        self.update_hostname(client=client)
        self.configure_motd_logo(client=client)
        self.stop_journald_log_storage(client=client)
        self.create_service_to_set_ram(client=client)
        self.create_customize_certs_service_files(client=client)

        logger.info_success("AMI customization process finished")

    @remote_connection
    def create_wazuh_user(self, client: paramiko.SSHClient | None = None) -> str:
        """
        Create the main Wazuh user on the Amazon Machine Image (AMI) and change
        the inventory user to the new Wazuh user.
        Also, modify the sudoers file to allow the new user to execute commands
        as root without a password and add the user's SSH public key to the authorized_keys file.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute commands on the remote system.

        Returns:
            str: The name of the created Wazuh user.
        """

        logger.debug_title("Starting AMI customization process")
        logger.debug(f"Creating Wazuh user: {self.wazuh_user}")

        command = f"""
        sudo adduser {self.wazuh_user}
        sudo mkdir -p /home/{self.wazuh_user}/.ssh
        sudo chown -R {self.wazuh_user}:{self.wazuh_user} /home/{self.wazuh_user}/.ssh
        sudo chmod 700 /home/{self.wazuh_user}/.ssh
        sudo touch /home/{self.wazuh_user}/.ssh/authorized_keys
        sudo chmod 600 /home/{self.wazuh_user}/.ssh/authorized_keys
        sudo cp /home/{self.instance_username}/.ssh/authorized_keys /home/{self.wazuh_user}/.ssh/authorized_keys
        sudo chown {self.wazuh_user}:{self.wazuh_user} /home/{self.wazuh_user}/.ssh/authorized_keys
        """

        _, error_output = exec_command(command=command, client=client)

        if error_output:
            logger.error(f'Failed to create wazuh user "{self.wazuh_user}"')
            raise RuntimeError(f'Failed to create Wazuh user "{self.wazuh_user}": {error_output}')

        modify_file(
            filepath=Path("/etc/sudoers.d/90-cloud-init-users"),
            replacements=[(r"ec2-user", self.wazuh_user)],
            client=client,
        )

        logger.debug(f"Changing inventory user to {self.wazuh_user}")

        self.inventory.ansible_user = self.wazuh_user

        logger.info_success(f'Wazuh user "{self.wazuh_user}" created successfully')

        return self.wazuh_user

    def remove_default_instance_user(self, client: paramiko.SSHClient) -> None:
        """
        Removes the default instance user from the system.

        This method terminates any processes associated with the default instance user
        and deletes the user account along with its home directory.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute commands on the remote system.

        Returns:
            None
        """

        logger.debug(f"Removing default instance user: {self.instance_username}")

        command = f"""
        sudo pkill -9 -u {self.instance_username}
        sleep 2
        sudo pkill -9 -u {self.instance_username} 2>/dev/null || true
        sudo userdel -r {self.instance_username}
        """

        _, error_output = exec_command(command=command, client=client)

        if error_output:
            logger.error(f'Failed to remove default instance user "{self.instance_username}"')
            raise RuntimeError(f'Failed to remove default instance user "{self.instance_username}": {error_output}')

        logger.info_success(f'Default instance user "{self.instance_username}" removed successfully')

    def configure_cloud_cfg(self, client: paramiko.SSHClient) -> None:
        """
        Configures the cloud-init configuration file on a remote machine via SSH.

        This method modifies the cloud-init configuration file to set specific user details
        and disables hostname updates. It then executes a series of cloud-init commands
        to apply the changes.

        Args:
            client (paramiko.SSHClient): An active SSH client connection to the remote machine.

        Returns:
            None
        """

        logger.debug(f"Configuring cloud config file: {self.cloud_config_path}")
        replacements = [
            (r"gecos: .*", "gecos: Wazuh AMI User"),
            (r"^[ \t]*name:\s*.*$", f"     name: {self.wazuh_user}"),
            (r"- set_hostname\n", ""),
            (r"\s*- update_hostname", ""),
            (r"preserve_hostname: false", "preserve_hostname: true"),
        ]
        command = """
        sudo cloud-init clean
        sudo cloud-init init
        """
        modify_file(filepath=self.cloud_config_path, replacements=replacements, client=client)

        logger.debug("Executing cloud-init commands")

        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error configuring cloud config")
            raise RuntimeError(f"Error configuring cloud config: {error_output}")

        logger.info_success("Cloud config file configured successfully")

    def update_hostname(self, client: paramiko.SSHClient) -> None:
        """
        Updates the hostname of a remote machine using the provided SSH client.

        Args:
            client (paramiko.SSHClient): An active SSH client connected to the target machine.

        Returns:
            None
        """

        logger.debug("Updating hostname")
        command = f"sudo hostnamectl set-hostname {self.wazuh_hostname}"

        _, error_output = exec_command(command=command, client=client)

        if error_output:
            logger.error("Error updating hostname")
            raise RuntimeError(f"Error updating hostname: {error_output}")
        logger.info_success(f'Hostname updated successfully to "{self.wazuh_hostname}"')

    def check_instance_updates(self, client: paramiko.SSHClient) -> bool:
        """
        Checks for updates on the instance by verifying the presence of the update motd file.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute the command on the remote instance.

        Returns:
            bool: True if updates are available, False if the instance is up to date.
        """

        logger.debug("Checking for instance updates")

        command = f"sudo cat {self.instance_update_logo_path}"
        output, error_output = exec_command(command=command, client=client)

        if error_output and "No such file or directory" in error_output:
            logger.error("Error checking instance updates")
            raise RuntimeError(f"Error checking instance updates: {error_output}")

        if output:
            logger.warning("Instance has updates available")
            return True

        logger.info("Instance is up to date")

        return False

    def update_instance(self, client: paramiko.SSHClient) -> None:
        """
        Updates the instance by running system update commands via SSH.

        This method connects to a remote instance using the provided SSH client
        and executes commands to update the system packages.

        Args:
            client (paramiko.SSHClient): An active SSH client connected to the instance.

        Returns:
            None
        """

        logger.debug("Updating instance")
        command = """
        sudo yum update -y
        sudo dnf upgrade --assumeyes --releasever=latest
        """

        _, error_output = exec_command(command=command, client=client)
        if error_output and "WARNING" not in error_output:
            logger.error("Error updating instance")
            raise RuntimeError(f"Error updating instance: {error_output}")

        logger.info_success("Instance updated successfully")

    def configure_motd_logo(self, client: paramiko.SSHClient) -> None:
        """
        Configures the Message of the Day (MOTD) logo on the instance.

        This method checks for available updates on the instance, applies updates if necessary,
        removes the update-related MOTD logo, and sets the Wazuh logo as the MOTD.

        Args:
            client (paramiko.SSHClient): An active SSH client connected to the instance.

        Returns:
            None
        """

        available_updates = self.check_instance_updates(client=client)
        if available_updates:
            self.update_instance(client=client)

        self._set_wazuh_logo(client=client)

    def _set_wazuh_logo(self, client: paramiko.SSHClient) -> None:
        """
        Sets the Wazuh logo as the Message of the Day (MOTD) banner on a remote host.

        This method uploads a Wazuh banner file to a remote host using SFTP, moves it to the appropriate
        directory, sets the necessary permissions and ownership, and updates the MOTD priority file.

        Args:
            client (paramiko.SSHClient): An active SSH client connection to the remote host.

        Returns:
            None
        """

        logger.debug("Setting Wazuh logo")

        wazuh_banner_file_destination = f"{self.motd_scripts_directory}/{self.wazuh_banner_path.name}"

        temporal_file_path = f"/tmp/{self.wazuh_banner_path.name}"
        sftp = client.open_sftp()
        try:
            sftp.put(str(self.wazuh_banner_path), temporal_file_path)
        except Exception as e:
            logger.error("Error uploading Wazuh banner to the remote host")
            raise RuntimeError(f"Error uploading Wazuh banner to the remote host: {str(e)}") from e
        finally:
            sftp.close()

        command = f"""
            sudo mv {temporal_file_path} {wazuh_banner_file_destination}
            sudo chmod 755 {wazuh_banner_file_destination}
            sudo chown root:root {wazuh_banner_file_destination}
            sudo rm -f {self.default_motd_file_path}
            """

        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error setting Wazuh motd banner")
            raise RuntimeError(f"Error setting Wazuh motd banner: {error_output}")

        logger.info_success("Wazuh motd banner set successfully")

    def stop_journald_log_storage(self, client: paramiko.SSHClient) -> None:
        """
        Stops journald log storage by modifying the journald configuration file and restarting the service.

        This method updates the journald configuration to disable persistent log storage and ensures
        that logs are forwarded to syslog. It then restarts the `systemd-journald` service and flushes
        the journal logs to apply the changes.

        Args:
            client (paramiko.SSHClient): An active SSH client used to execute commands on the remote system.

        Returns:
            None
        """

        logger.debug("Stopping journald log storage")

        parameters = [
            ("#Storage=auto", "Storage=none"),
            ("#ForwardToSyslog=yes", "ForwardToSyslog=yes"),
        ]
        modify_file(filepath=self.journald_file_path, replacements=parameters, client=client)

        command = """
        sudo systemctl restart systemd-journald
        sudo journalctl --flush
        """
        _, error_output = exec_command(command=command, client=client)

        if error_output:
            logger.error("Error stopping journald log storage")
            raise RuntimeError(f"Error stopping journald log storage: {error_output}")

    def create_ami_custom_service(self, file_local_path: Path, client: paramiko.SSHClient) -> None:
        """
        Creates a systemd service on the remote host using the provided local service file.
        This method uploads the service file to the remote host, moves it to the appropriate
        systemd services directory, sets the necessary permissions and ownership, and enables the service.
        Args:
            file_local_path (Path): The local path of the service file to be uploaded.
            client (paramiko.SSHClient): An active SSH client connected to the remote host.
        Returns:
            None
        """

        logger.debug(f'Creating "{file_local_path.name}" service')

        sftp = client.open_sftp()
        tmp_service_path = f"/tmp/{file_local_path.name}"
        try:
            sftp.put(str(file_local_path), tmp_service_path)
        except Exception as e:
            logger.error("Error uploading files to the remote host")
            raise RuntimeError(f"Error uploading files to the remote host: {str(e)}") from e
        finally:
            sftp.close()

        command = f"""
        sudo mv {tmp_service_path} {self.systemd_services_path}/{file_local_path.name}
        sudo chmod 755 {self.systemd_services_path}/{file_local_path.name}
        sudo chown root:root {self.systemd_services_path}/{file_local_path.name}
        sudo systemctl --quiet enable {file_local_path.name}
        """
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error(f"Error creating service {file_local_path.name}")
            raise RuntimeError(f"Error creating service {file_local_path.name}: {error_output}")

        logger.info_success(f'"{file_local_path.name.split(".")[0]}" service created successfully')

    def create_service_to_set_ram(self, client: paramiko.SSHClient) -> None:
        """
        Creates and configures a systemd service to set the appropiate ram usage for the indexer's jvm
        on a remote host.

        This method uploads the necessary service and script files to the remote host,
        moves them to their appropriate locations, sets the required permissions, and
        enables the service using systemd.

        Args:
            client (paramiko.SSHClient): An active SSH client connected to the remote host.

        Returns:
            None
        """

        sftp = client.open_sftp()
        tmp_ram_script_path = f"/tmp/{self.local_set_ram_script_path.name}"
        try:
            sftp.put(str(self.local_set_ram_script_path), tmp_ram_script_path)

        except Exception as e:
            logger.error("Error uploading files to the remote host")
            raise RuntimeError(f"Error uploading files to the remote host: {str(e)}") from e
        finally:
            sftp.close()

        command = f"""
        sudo mv {tmp_ram_script_path} {self.ram_service_script_destination_path}/{self.local_set_ram_script_path.name}
        sudo chmod 755 {self.ram_service_script_destination_path}/{self.local_set_ram_script_path.name}
        """
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error creating script for set RAM service")
            raise RuntimeError(f"Error creating script for set RAM service: {error_output}")

        self.create_ami_custom_service(
            file_local_path=self.local_update_indexer_heap_service_path,
            client=client,
        )

    def create_customize_certs_service_files(self, client: paramiko.SSHClient) -> None:
        """
        Create the customize certificates service and timer files on the remote server.
        This method uploads the service and timer files to the remote server and enables them.
        Args:
            client (paramiko.SSHClient): The SSH client used for the connection.
        """

        self.create_ami_custom_service(
            file_local_path=self.local_customize_certs_service_path,
            client=client,
        )
        self.create_ami_custom_service(
            file_local_path=self.local_customize_certs_timer_path,
            client=client,
        )
