from dataclasses import dataclass
from typing import List
from pydantic import AnyUrl
from urllib.parse import urlparse
import os
from generic import remote_connection
from provisioner.utils.enums import Component
from utils import Logger
from .models import CertsInfo, ComponentInfo, Inventory
from .utils import Component_arch, Package_type, Package_manager, RemoteDirectories

import paramiko

logger = Logger("Provisioner")

@dataclass
class Provisioner:
    inventory: Inventory
    certs: CertsInfo
    components: List[ComponentInfo]
    arch: Component_arch = Component_arch.X86_64
    package_type: Package_type = Package_type.RPM
    
    @property
    def package_manager(self):
        if self.package_type == Package_type.RPM:
            return Package_manager.YUM
        return Package_manager.APT

    @remote_connection
    def provision(self, client: paramiko.SSHClient = paramiko.SSHClient()):
        logger.debug_title("Starting provisioning")
        logger.debug_title("Provisioning certificates files")

        self.certs_tool_provision(client)
        self.certs_config_provision(client)

        for component in self.components:
            logger.debug_title(f"Starting provisioning for {component.name.replace('_', ' ')}")
            self.dependencies_provision(component, client)
            self.packages_provision(component, client)
    
    def certs_tool_provision(self, client: paramiko.SSHClient):
        logger.debug("Provisioning certs-tool")
        self.certificates_provision(self.certs.certs_tool_url, client)
    
    def certs_config_provision(self, client: paramiko.SSHClient):
        logger.debug("Provisioning certs-config")
        self.certificates_provision(self.certs.config_url, client)

    def dependencies_provision(self, component: ComponentInfo, client: paramiko.SSHClient):
        logger.debug_title(f"Provisioning dependencies for {component.name.replace('_', ' ')}")

        self.list_dependencies(component.dependencies, component.name)
        
        for dependency in component.dependencies:
            self.install_dependency(dependency, client) 
        
        if component.dependencies:
            logger.info_success(f"Dependencies for {component.name.replace('_', ' ')} installed successfully")    
        else:
            logger.info_success(f"There are no dependencies to install for {component.name.replace('_', ' ')}")

    def packages_provision(self, component: ComponentInfo, client: paramiko.SSHClient):
        logger.debug_title("Provisioning packages")
        logger.debug(f"Downloading {component.name.replace('_', ' ')} package")
        package_name= self.get_package_by_url(component.name, component.package_url, client)
        self.install_component(component.name, package_name, client)

    def certificates_provision(self, certs_file_url: AnyUrl, client: paramiko.SSHClient):
        parsed_url = urlparse(str(certs_file_url))
        filename = os.path.basename(parsed_url.path)
        command_template = "mkdir -p {dir} && curl -s -o {path} '{filename}'"

        command = command_template.format(dir=f"{RemoteDirectories.CERTS}", path=f"{RemoteDirectories.CERTS}/{filename}", filename=certs_file_url)
        stdin, stdout, stderr = client.exec_command(command=command)
        error_output = stderr.read().decode()
        
        if error_output:
            logger.error(f"Error downloading {filename}: {error_output}")
            raise Exception(f"Error downloading {filename}")
        
        logger.info_success(f"{filename} downloaded successfully")
 
    def list_dependencies(self, elements: List[str], component_name: str):
        debug_message = f"Necessary dependencies for {component_name.replace('_', ' ')}:"

        if not elements:
            debug_message += "\n\t\t\t(No dependencies found)"
        for element in elements:
            debug_message += f"\n\t\t\t- {element}"
            
        logger.debug(debug_message)
    
    def install_dependency(self, dependency: str, client: paramiko.SSHClient) -> None:
        command_template = "sudo dnf install -y {package_name}" if self.package_manager == Package_manager.YUM else "sudo apt-get install -y {package_name}"
        self.install_package(dependency, command_template, client)
                
    def install_component(self, component_name: Component, package_name: str, client: paramiko.SSHClient) -> None:
        command_template = "sudo dnf install -y {package_name}" if self.package_manager == Package_manager.YUM else "sudo dpkg -i {package_name}"
        full_package_path = f"{RemoteDirectories.PACKAGES}/{package_name}"
        self.install_package(full_package_path, command_template, client, component_name.replace('_', ' ').capitalize())
            
    def get_package_by_url(self, component_name: Component, package: AnyUrl, client: paramiko.SSHClient) -> str:
        package_name = f"{component_name}.{self.package_type}"
        command = f"mkdir -p {RemoteDirectories.PACKAGES} && curl -s -o {RemoteDirectories.PACKAGES}/{package_name} '{package}'"
        
        stdin, stdout, stderr = client.exec_command(command=command)
        stderr = stderr.read().decode()

        if stderr:
            logger.error(f"Error getting package: {stderr}")
            raise Exception("Error getting package")

        logger.info_success("Package downloaded successfully")
        return package_name

    def install_package(self, package_name: str, command_template: str, client: paramiko.SSHClient, package_alias: str | None = None) -> None:
        package_alias = package_alias or package_name
        logger.debug(f"Installing {package_alias}")

        stdin, stdout, stderr = client.exec_command(command_template.format(package_name=package_name))
        output = stdout.read().decode()
        error_output = stderr.read().decode()

        if not output:
            logger.info_success(f"{package_alias} package installed successfully")
        elif "is already installed" in output:
            logger.debug(f"{package_alias} is already installed")
        elif "WARNING" in error_output:
            logger.warning(f"{error_output}")
            logger.info_success(f"{package_alias} installed successfully")
        else:
            logger.error(f"Error installing {package_alias}: {error_output}")
            raise Exception(f"Error installing {package_alias}")
