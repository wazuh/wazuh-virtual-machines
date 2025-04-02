import sys
from dataclasses import dataclass
from pathlib import Path

import paramiko

from configurer.ami.ami_post_configurer import create_directory_structure, generate_yaml
from generic import remote_connection
from models import Inventory
from utils import CertificatesComponent, RemoteDirectories


@dataclass
class AmiPostCustomizer:
    inventory: Inventory
    envonment_name: str = "certs_env"
    custom_dir_base_path: str = "/etc"
    
    @remote_connection
    def create_custom_dir(self, client: paramiko.SSHClient | None = None):
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
        
        create_directory_structure(base_path=self.custom_dir_base_path, directory_template=directory_template, client=client)


if __name__ == "__main__":
    arguments = sys.argv[1:] 
    inventory_path = arguments[0]
    inventory = Inventory(inventory_path=Path(inventory_path))
    
    ami_post_customizer = AmiPostCustomizer(inventory=inventory)
    ami_post_customizer.create_custom_dir()
        
    
    