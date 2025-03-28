from dataclasses import dataclass
from pathlib import Path

import paramiko

from generic import exec_command, modify_file, remote_connection
from models import Inventory
from utils import Logger

logger = Logger("AmiCustomizer")


@dataclass
class AmiCustomizer:
    inventory: Inventory
    wazuh_banner_path: Path
    local_set_ram_script_path: Path
    local_update_indexer_heap_service_path: Path
    cloud_config_path: Path = Path("/etc/cloud/cloud.cfg")
    ssh_config_path: Path = Path("/etc/ssh/sshd_config")
    instance_update_logo_path: Path = Path("/etc/update-motd.d/70-available-updates")
    motd_priority_file = Path("/etc/motd")
    journald_file_path = Path("/etc/systemd/journald.conf")
    systemd_services_path = Path("/etc/systemd/system/")
    ram_service_script_destination_path = Path("/etc")
    instance_username: str = "ec2-user"
    wazuh_hostname: str = "wazuh-server"
    wazuh_user: str = "wazuh-user"
    wazuh_password: str = "wazuh"
    ssh_default_port: int = 22

    @remote_connection
    def customize(self, client: paramiko.SSHClient | None = None):
        if self.inventory.ansible_user != self.wazuh_user:
            raise Exception(f'Before customizing the AMI, the Wazuh user  "{self.wazuh_user}" must be created')

        self.remove_default_instance_user(client=client)  # type: ignore
        self.configure_cloud_cfg(client=client)  # type: ignore
        self.update_hostname(client=client)  # type: ignore
        self.configure_motd_logo(client=client)  # type: ignore
        self.stop_journald_log_storage(client=client)  # type: ignore
        self.create_service_to_set_ram(client=client)  # type: ignore

        logger.info_success("AMI customization process finished")

    @remote_connection
    def create_wazuh_user(self, client: paramiko.SSHClient | None = None) -> str:
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
            logger.error(f'Error creating wazuh user "{self.wazuh_user}"')
            raise RuntimeError(f'Error creating wazuh user "{self.wazuh_user}": {error_output}')

        modify_file(
            filepath=Path("/etc/sudoers.d/90-cloud-init-users"),
            replacements=[(r"ec2-user", self.wazuh_user)],
            client=client,
        )

        logger.debug(f"Changing inventory user to {self.wazuh_user}")

        self.inventory.ansible_user = self.wazuh_user

        logger.info_success(f'Wazuh user "{self.wazuh_user}" created successfully')

        return self.wazuh_user

    def remove_default_instance_user(self, client: paramiko.SSHClient):
        logger.debug(f"Removing default instance user: {self.instance_username}")

        command = f"""
        sudo pkill -u {self.instance_username}
        sudo userdel -r {self.instance_username}
        """

        _, error_output = exec_command(command=command, client=client)

        if error_output:
            logger.error(f'Error removing default instance user "{self.instance_username}"')
            raise RuntimeError(f'Error removing default instance user "{self.instance_username}": {error_output}')

        logger.info_success(f'Default instance user "{self.instance_username}" removed successfully')

    def configure_cloud_cfg(self, client: paramiko.SSHClient):
        logger.debug(f"Configuring cloud config file: {self.cloud_config_path}")
        replacements = [
            (r"gecos: .*", "gecos: Wazuh AMI User"),
            (r"name: .*", f"name: {self.wazuh_user}"),
            (r"- set_hostname\n", ""),
            (r"\s*- update_hostname", "\n - preserve_hostname: true"),
        ]
        command = """
        sudo cloud-init clean
        sudo cloud-init init
        sudo cloud-init modules --mode=config
        sudo cloud-init modules --mode=final
        """
        modify_file(filepath=self.cloud_config_path, replacements=replacements, client=client)

        logger.debug("Executing cloud-init commands")

        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error configuring cloud config")
            raise RuntimeError(f"Error configuring cloud config {error_output}")

        logger.info_success("Cloud config file configured successfully")

    def update_hostname(self, client: paramiko.SSHClient):
        logger.debug("Updating hostname")
        command = f"sudo hostnamectl set-hostname {self.wazuh_hostname}"

        _, error_output = exec_command(command=command, client=client)

        if error_output:
            logger.error("Error updating hostname")
            raise RuntimeError(f"Error updating hostname {error_output}")
        logger.info_success(f'Hostname updated successfully to "{self.wazuh_hostname}"')

    def check_instance_updates(self, client: paramiko.SSHClient):
        logger.debug("Checking for instance updates")

        command = f"sudo cat {self.instance_update_logo_path}"
        output, error_output = exec_command(command=command, client=client)

        if error_output and "No such file or directory" in error_output:
            logger.error("Error checking for instance updates")
            raise RuntimeError(f"Error checking for instance updates {error_output}")

        if output:
            logger.warning("Instance updates availables")
            return True

        logger.info("Instance is up to date")

        return False

    def update_instance(self, client: paramiko.SSHClient):
        logger.debug("Updating instance")
        command = """
        sudo yum update -y
        sudo dnf upgrade --assumeyes --releasever=latest
        """

        _, error_output = exec_command(command=command, client=client)
        if error_output and "WARNING" not in error_output:
            logger.error("Error updating instance")
            raise RuntimeError(f"Error updating instance {error_output}")

        logger.info_success("Instance updated successfully")

    def configure_motd_logo(self, client: paramiko.SSHClient):
        available_updates = self.check_instance_updates(client=client)
        if available_updates:
            self.update_instance(client=client)
            self._remove_update_motd_logo(client=client)

        self._set_wazuh_logo(client=client)

    def _set_wazuh_logo(self, client: paramiko.SSHClient):
        logger.debug("Setting Wazuh logo")

        wazuh_banner_file_destination = f"/usr/lib/motd.d/{self.wazuh_banner_path.name}"

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
            sudo cat {wazuh_banner_file_destination} | sudo tee {self.motd_priority_file} > /dev/null
            """

        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error setting Wazuh motd banner")
            raise RuntimeError("Error setting Wazuh motd banner")

        logger.info_success("Wazuh motd banner set successfully")

    def _remove_update_motd_logo(self, client: paramiko.SSHClient):
        logger.debug("Removing update motd logo")

        _, error_output = exec_command(f"sudo rm -f {self.instance_update_logo_path}", client=client)

        if error_output:
            logger.error(f"Error removing update motd logo in path {self.instance_update_logo_path}")
            raise RuntimeError(f"Error removing update motd logo {error_output}")

        logger.info_success("Update motd logo removed successfully")

    def stop_journald_log_storage(self, client: paramiko.SSHClient):
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

    def create_service_to_set_ram(self, client: paramiko.SSHClient):
        logger.debug(f'Creating "{self.local_update_indexer_heap_service_path.name}" service')

        sftp = client.open_sftp()
        tmp_service_path = f"/tmp/{self.local_update_indexer_heap_service_path.name}"
        tmp_ram_script_path = f"/tmp/{self.local_set_ram_script_path.name}"
        try:
            sftp.put(str(self.local_update_indexer_heap_service_path), tmp_service_path)
            sftp.put(str(self.local_set_ram_script_path), tmp_ram_script_path)

        except Exception as e:
            logger.error("Error uploading files to the remote host")
            raise RuntimeError(f"Error uploading files to the remote host: {str(e)}") from e
        finally:
            sftp.close()

        command = f"""
        sudo mv {tmp_service_path} {self.systemd_services_path}/{self.local_update_indexer_heap_service_path.name}
        sudo mv {tmp_ram_script_path} {self.ram_service_script_destination_path}/{self.local_set_ram_script_path.name}
        sudo chmod 755 {self.ram_service_script_destination_path}/{self.local_set_ram_script_path.name}
        sudo chmod 755 {self.systemd_services_path}/{self.local_update_indexer_heap_service_path.name}
        sudo chown root:root {self.systemd_services_path}/{self.local_update_indexer_heap_service_path.name}
        sudo systemctl --quiet enable {self.local_update_indexer_heap_service_path.name}
        """
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error creating service to set RAM")
            raise RuntimeError(f"Error creating service to set RAM: {error_output}")

        logger.info_success('"updateIndexerHeap" service created successfully')
