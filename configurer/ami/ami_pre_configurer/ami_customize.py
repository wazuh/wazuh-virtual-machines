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
    cloud_config_path: Path = Path("/etc/cloud/cloud.cfg")
    ssh_config_path: Path = Path("/etc/ssh/sshd_config")
    instance_username: str = "ec2-user"
    wazuh_hostname: str = "wazuh-server"
    wazuh_user: str = "wazuh-user"
    wazuh_password: str = "wazuh"
    ssh_default_port: int = 22

    @remote_connection
    def customize(self, client: paramiko.SSHClient | None = None):
        if self.inventory.ansible_user != self.wazuh_user:
            raise Exception(f"Before customizing the AMI, the Wazuh user  \"{self.wazuh_user}\" must be created")
        
        logger.debug_title("Starting AMI customization process")
        self.remove_default_instance_user(client=client)  # type: ignore
        self.configure_cloud_cfg(client=client)  # type: ignore
        self.update_hostname(client=client)  # type: ignore
        self.set_wazuh_logo(client=client)  # type: ignore
        

        logger.info_success("AMI customization process finished")

    @remote_connection
    def create_wazuh_user(self, client: paramiko.SSHClient | None = None):
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

        output, error_output = exec_command(command=command, client=client)

        if error_output:
            logger.error(f"Error creating wazuh user \"{self.wazuh_user}\"")
            raise RuntimeError(f"Error creating wazuh user \"{self.wazuh_user}\": {error_output}")
        
        modify_file(filepath=Path("/etc/sudoers.d/90-cloud-init-users"), replacements=[(r"ec2-user", self.wazuh_user)], client=client)
        
        logger.debug(f"Changing inventory user to {self.wazuh_user}")

        self.inventory.ansible_user = self.wazuh_user
        
        logger.info_success(f"Wazuh user \"{self.wazuh_user}\" created successfully")


    def remove_default_instance_user(self, client: paramiko.SSHClient):
        logger.debug(f"Removing default instance user: {self.instance_username}")
        
        command = f"""
        sudo pkill -u {self.instance_username}
        sudo userdel -r {self.instance_username}
        """
        
        output, error_output = exec_command(command=command, client=client)
        
        if error_output:
            logger.error(f"Error removing default instance user \"{self.instance_username}\"")
            raise RuntimeError(f"Error removing default instance user \"{self.instance_username}\": {error_output}")
        
        logger.info_success(f"Default instance user \"{self.instance_username}\" removed successfully")
        


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

        output, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error configuring cloud config")
            raise RuntimeError(f"Error configuring cloud config {error_output}")

        logger.info_success("Cloud config file configured successfully")


    def update_hostname(self, client: paramiko.SSHClient):
        logger.debug("Updating hostname")
        command = f"sudo hostnamectl set-hostname {self.wazuh_hostname}"

        output, error_output = exec_command(command=command, client=client)

        if error_output:
            logger.error("Error updating hostname")
            raise RuntimeError(f"Error updating hostname {error_output}")
        logger.info_success(f'Hostname updated successfully to "{self.wazuh_hostname}"')



    def set_wazuh_logo(self, client: paramiko.SSHClient):
        logger.debug("Setting Wazuh logo")

        default_instance_logo_path = Path("/usr/lib/motd.d/30-banner")
        
        banner_file_destination = f"/usr/lib/motd.d/{self.wazuh_banner_path.name}"
        if client:
            temporal_file_path = f"/tmp/{self.wazuh_banner_path.name}"
            sftp = client.open_sftp()
            try:
                sftp.put(str(self.wazuh_banner_path), temporal_file_path)
                command = f"sudo mv {temporal_file_path} {banner_file_destination}"
            finally:
                sftp.close()
        else:
            command = f"sudo cp {self.wazuh_banner_path} {banner_file_destination}"

        command += f" && sudo rm {default_instance_logo_path}"

        output, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error setting Wazuh MOTD banner")
            raise RuntimeError(f"Error setting Wazuh MOTD banner {error_output}")

        logger.info_success("Wazuh MOTD banner set successfully")

    def clean_up(self, client: paramiko.SSHClient | None = None):
        logger.debug("Cleaning up")
        # command = """
        #     sudo yum clean all
        #     sudo rm -rf /var/log/*
        #     sudo rm -rf /tmp/*"
        #     sudo rm -rf /var/cache/yum/*
        #     sudo rm ~/.ssh/*"
        #     sudo yum autoremove -y
        #     sudo rm -rf /root/.ssh/*
        #     cat /dev/null > /root/.bash_history && history -c
        #     cat /dev/null > ~/.bash_history && history -c
        # """
        # logger.info_success("Clean up finished successfully")

if __name__ == "__main__":
    inventory = Inventory(Path("/home/henry/work-wazuh/wazuh-repos/wazuh-virtual-machines/provisioner/inventory.yaml"))
    # logger.debug(f"actual path: {Path(__file__).parent / "static" / "40-wazuh-banner"}")  
    ami_customizer = AmiCustomizer(inventory=inventory, wazuh_banner_path=Path(__file__).parent / "static" / "40-wazuh-banner")
    ami_customizer.create_wazuh_user()
    ami_customizer.customize()
