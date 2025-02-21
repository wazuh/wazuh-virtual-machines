from pathlib import Path

import pydantic_core
import yaml
from pydantic import BaseModel, SecretStr


class Inventory(BaseModel):
    """
    Inventory model to represent and manage Ansible inventory data.

    Attributes:
        ansible_host_name (str): The name of the Ansible host.
        ansible_user (str): The Ansible user.
        ansible_password (SecretStr | None): The Ansible password, if any.
        ansible_host (str): The Ansible host address.
        ansible_connection (str): The Ansible connection type, default is "ssh".
        ansible_port (int): The port number for the Ansible connection.
        ansible_ssh_private_key_file (Path | None): The path to the SSH private key file, if any.
        ansible_ssh_common_args (str | None): Additional SSH arguments, if any.
    """
    ansible_host_name: str
    ansible_user: str
    ansible_password: SecretStr | None = None
    ansible_host: str
    ansible_connection: str = "ssh"
    ansible_port: int
    ansible_ssh_private_key_file: Path | None = None
    ansible_ssh_common_args: str | None = None

    def __init__(self, inventory_path: Path, host_name: str | None = None):
        """
        Initialize the inventory object fwith an ansible inventory data.

        Args:
            inventory_path (Path): The path to the inventory file.
            host_name (str | None, optional): The name of the host to look for in the inventory. Defaults to None.

        Raises:
            FileNotFoundError: If the inventory file is not found at the specified path.
        """
        try:
            with open(inventory_path) as f:
                data = yaml.safe_load(f)
                host_data = self._check_inventory(data, host_name)
                super().__init__(**host_data)
        except FileNotFoundError as err:
            raise FileNotFoundError(
                f"Inventory file not found at {inventory_path}"
            ) from err
        except pydantic_core._pydantic_core.ValidationError as err:
            raise ValueError("Invalid inventory host parameters. Use the correct ones") from err

    def _check_inventory(self, inventory: dict, host_name: str | None = None) -> dict:
        """
        Check and retrieve host data from the inventory.

        This method validates the structure of the provided inventory dictionary and retrieves
        the data for a specified host. If no host name is provided, it defaults to the first host
        in the inventory.

        Args:
            inventory (dict): The inventory dictionary to check.
            host_name (str | None, optional): The name of the host to retrieve data for. Defaults to None.

        Returns:
            dict: The data for the specified host.

        Raises:
            ValueError: If the 'all' section is missing from the inventory.
            KeyError: If the 'hosts' section is missing from the inventory or if the specified host is not found.
        """
        if inventory.get("all") is None:
            raise ValueError("Invalid inventory format: 'all' section is missing")
        hosts = inventory.get("all", {}).get("hosts", None)

        if hosts is None:
            raise KeyError("Invalid inventory format: 'hosts' section is missing")

        if host_name is None:
            host_name = list(hosts.keys())[0]

        host_data = hosts.get(host_name, None)
        if host_data is None:
            raise KeyError(f"Host {host_name} not found in inventory file")
        
        host_data["ansible_host_name"] = host_name

        return host_data

    def to_dict(self) -> dict:
        """
        Converts the inventory object to a dictionary representation.

        Returns:
            dict: A dictionary with the ansible host name as the key and a nested dictionary containing
                  ansible user, password, host, connection type, port, SSH private key file, and SSH common args.
        """
        return {
            self.ansible_host_name: {
                "ansible_user": self.ansible_user,
                "ansible_password": self.ansible_password or None,
                "ansible_host": self.ansible_host,
                "ansible_connection": self.ansible_connection,
                "ansible_port": self.ansible_port,
                "ansible_ssh_private_key_file": str(self.ansible_ssh_private_key_file),
                "ansible_ssh_common_args": self.ansible_ssh_common_args,
            }
        }
