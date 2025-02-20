from pathlib import Path

import yaml
from pydantic import BaseModel, SecretStr


class Inventory(BaseModel):
    ansible_host_name: str
    ansible_user: str
    ansible_password: SecretStr | None = None
    ansible_host: str
    ansible_connection: str = "ssh"
    ansible_port: int
    ansible_ssh_private_key_file: Path | None = None
    ansible_ssh_common_args: str | None = None
    
    def __init__(self, inventory_path: Path, host_name: str | None = None):
        try:
            with open(inventory_path) as f:
                data = yaml.safe_load(f)
                host_data = self._check_inventory(data, host_name)
                super().__init__(**host_data)
        except FileNotFoundError as err:
            raise FileNotFoundError(f"Inventory file not found at {inventory_path}") from err

    def _check_inventory(self, inventory: dict, host_name: str | None = None) -> dict:
        if inventory.get("all") is None:
            raise ValueError("Invalid inventory format: 'all' section is missing")
        hosts = inventory.get("all", {}).get("hosts")

        if hosts is None:
            raise KeyError("Invalid inventory format: 'hosts' section is missing")
        
        if host_name is None:
            host_name = list(hosts.keys())[0]
        
        host_data = hosts.get(host_name)
        host_data["ansible_host_name"] = host_name

        if host_data is None:
            raise KeyError(f"Host {host_name} not found in inventory file")
        
        return host_data
    
    def to_dict(self) -> dict:
        return {
            self.ansible_host_name: {
                "ansible_user": self.ansible_user,
                "ansible_password": self.ansible_password or None,
                "ansible_host": self.ansible_host,
                "ansible_connection": self.ansible_connection,
                "ansible_port": self.ansible_port,
                "ansible_ssh_private_key_file": str(self.ansible_ssh_private_key_file),
                "ansible_ssh_common_args": self.ansible_ssh_common_args
            }
        }
