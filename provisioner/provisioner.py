from dataclasses import dataclass

import paramiko
from pydantic import AnyUrl

from generic import exec_command, remote_connection
from models import Inventory
from provisioner.models import CertsInfo, ComponentInfo
from provisioner.utils import Component_arch, Package_manager, Package_type
from utils import CertificatesComponent, Component, Logger, RemoteDirectories

logger = Logger("Provisioner")


@dataclass
class Provisioner:
    """
    A class to handle the provisioning of components, certificates, and dependencies on remote machines.

    Attributes:
        inventory (Inventory): The ansible inventory to connect to the instance.
        certs (CertsInfo): Information about certificates (certs_tool and config file).
        components (List[ComponentInfo]): List of Wazuh components to be provisioned.
        arch (Component_arch): The architecture of the components. Default is X86_64.
        package_type (Package_type): The type of package to be used. Default is RPM.

    Properties:
        package_manager (Package_manager): The package manager to be used based on the package type.
    """

    inventory: Inventory | None
    certs: CertsInfo
    components: list[ComponentInfo]
    arch: Component_arch = Component_arch.X86_64
    package_type: Package_type = Package_type.RPM

    @property
    def package_manager(self):
        if self.package_type == Package_type.RPM:
            return Package_manager.YUM
        return Package_manager.APT

    @remote_connection
    def provision(self, client: paramiko.SSHClient | None = None) -> None:
        """
        Provisions the necessary certificates and component packages to the client instance.

        This method performs the following steps:
        1. Logs the start of the provisioning process.
        2. Provisions the certs_tool using `certs_tool_provision`.
        3. Provision the config file using `certs_config_provision`.
        4. Iterates over each component and performs the following:
            a. Logs the start of provisioning for the component.
            b. Provisions dependencies for the component using `dependencies_provision`.
            c. Provisions packages for the component using `packages_provision`.

        Args:
            client (paramiko.SSHClient, optional): The SSH client to use for provisioning. Defaults to a new instance of `paramiko.SSHClient`.
        """
        logger.debug_title("Starting provisioning")
        logger.debug_title("Provisioning certificates files")

        self.certs_tool_provision(client)
        self.certs_config_provision(client)

        logger.debug_title("Provisioning special dependencies")

        self.special_dependencies_provision(client)

        for component in self.components:
            logger.debug_title(f"Starting provisioning for {component.name.replace('_', ' ')}")
            self.dependencies_provision(component, client)
            self.packages_provision(component, client)

    def certs_tool_provision(self, client: paramiko.SSHClient | None = None) -> None:
        """
        Provisions the certs_tool on the specified client.

        This method uses the provided SSH client to connect to a remote machine
        and provision the certs_tool by calling the `certificates_provision`
        method with the appropriate URL.

        Args:
            client (paramiko.SSHClient): The SSH client used to connect to the remote machine.
        """
        self.certificates_provision(self.certs.certs_tool_url, CertificatesComponent.CERTS_TOOL, client)

    def certs_config_provision(self, client: paramiko.SSHClient | None = None) -> None:
        """
        Provisions the certs config file on the remote client.

        This method uses the provided SSH client to connect to a remote machine
        and provision the certs config file by calling the `certificates_provision`
        method with the appropriate URL.

        Args:
            client (paramiko.SSHClient): The SSH client used to connect to the remote machine.

        Returns:
            None
        """
        self.certificates_provision(self.certs.config_url, CertificatesComponent.CONFIG, client)

    def special_dependencies_provision(self, client: paramiko.SSHClient | None = None) -> None:
        """
        Provisions special dependencies on the specified client. These dependencies are installed
        in a special way different from apt-get or dnf install. They can be dependencies of a
        component itself or necessary for the execution of a module.
        For now the special dependencies are:
        - yq
        Args:
            client (paramiko.SSHClient): The SSH client used to connect to the remote machine.

        Returns:
            None
        """

        # Install yq

        yq_arch = "amd64" if self.arch in [Component_arch.X86_64, Component_arch.AMD64] else "arm64"
        command = f"""
            sudo wget -q https://github.com/mikefarah/yq/releases/latest/download/yq_linux_{yq_arch} -O /usr/bin/yq
            sudo chmod +x /usr/bin/yq
        """
        self.install_package("yq", command, client)

    def dependencies_provision(self, component: ComponentInfo, client: paramiko.SSHClient | None = None) -> None:
        """
        Provisions the dependencies for a given component by installing each dependency on the specified SSH client.

        Args:
            component (ComponentInfo): The component for which dependencies need to be provisioned.
            client (paramiko.SSHClient): The SSH client used to install the dependencies.

        Returns:
            None
        """
        logger.debug_title(f"Provisioning dependencies for {component.name.replace('_', ' ')}")

        self.list_dependencies(component.dependencies, component.name)

        for dependency in component.dependencies:
            self.install_dependency(dependency, client)

        if component.dependencies:
            logger.info_success(f"Dependencies for {component.name.replace('_', ' ')} installed successfully")
        else:
            logger.info_success(f"There are no dependencies to install for {component.name.replace('_', ' ')}")

    def packages_provision(self, component: ComponentInfo, client: paramiko.SSHClient | None = None) -> None:
        """
        Provisions the specified component by downloading and installing its package.

        Args:
            component (ComponentInfo): The component information including name and package URL.
            client (paramiko.SSHClient): The SSH client used to connect to the remote machine.

        Returns:
            None
        """
        logger.debug_title("Provisioning packages")
        logger.debug(f"Downloading {component.name.replace('_', ' ')} package")

        package_name = self.get_package_by_url(component.name, component.package_url, client)

        command_template = (
            "sudo dnf install -y {package_name}"
            if self.package_manager == Package_manager.YUM
            else "sudo dpkg -i {package_name}"
        )
        full_package_path = f"{RemoteDirectories.PACKAGES}/{package_name}"

        self.install_package(
            full_package_path,
            command_template,
            client,
            component.name.replace("_", " ").capitalize(),
        )

    def certificates_provision(
        self, certs_file_url: AnyUrl, filename: str, client: paramiko.SSHClient | None = None
    ) -> None:
        """
        Downloads a certificate file (certs_tool or config) from a given URL and saves it to a remote directory on a server.

        Args:
            certs_file_url (AnyUrl): The URL of the certificate file to be downloaded.
            client (paramiko.SSHClient): An active SSH client connected to the remote server.

        Raises:
            Exception: If there is an error during the download process.

        Logs:
            Error message if the download fails.
            Success message if the download is successful.
        """
        logger.debug(f"Provisioning {filename}")

        command_template = "mkdir -p {dir} && curl -s -o {path} '{certs_file_url}'"

        command = command_template.format(
            dir=f"{RemoteDirectories.CERTS}",
            path=f"{RemoteDirectories.CERTS}/{filename}",
            certs_file_url=certs_file_url,
        )
        output, error_output = exec_command(command=command, client=client)

        if error_output:
            logger.error(f"Error downloading {filename}: {error_output}")
            raise RuntimeError(f"Error downloading {filename}")

        logger.info_success(f"{filename} downloaded successfully")

    def list_dependencies(self, elements: list[str], component_name: str) -> None:
        """
        Logs the necessary dependencies for a given component.

        Args:
            elements (List[str]): A list of dependency names.
            component_name (str): The name of the component for which dependencies are listed.

        Returns:
            None
        """
        debug_message = f"Necessary dependencies for {component_name.replace('_', ' ')}:"

        if not elements:
            debug_message += "\n\t\t\t\t\t(No dependencies found)"
        for element in elements:
            debug_message += f"\n\t\t\t\t\t- {element}"

        logger.debug(debug_message)

    def install_dependency(self, dependency: str, client: paramiko.SSHClient | None = None) -> None:
        """
        Installs a specified dependency on a remote machine using the appropriate package manager.

        Args:
            dependency (str): The name of the dependency to install.
            client (paramiko.SSHClient): The SSH client connected to the remote machine.

        Returns:
            None
        """
        command_template = (
            "sudo dnf install -y {package_name}"
            if self.package_manager == Package_manager.YUM
            else "sudo apt-get install -y {package_name}"
        )
        self.install_package(dependency, command_template, client)

    def get_package_by_url(
        self,
        component_name: Component,
        package: AnyUrl,
        client: paramiko.SSHClient | None = None,
    ) -> str:
        """
        Downloads a package from a given URL to a remote directory using an SSH client.

        Args:
            component_name (Component): The name of the component for which the package is being downloaded.
            package (AnyUrl): The URL from which to download the package.
            client (paramiko.SSHClient): The SSH client used to execute the remote command.

        Returns:
            str: The name of the downloaded package.

        Raises:
            Exception: If there is an error during the package download process.
        """
        package_name = f"{component_name}.{self.package_type}"
        command = f"mkdir -p {RemoteDirectories.PACKAGES} && curl -s -o {RemoteDirectories.PACKAGES}/{package_name} '{package}'"

        output, error_output = exec_command(command=command, client=client)

        if error_output:
            logger.error(f"Error getting package: {error_output}")
            raise RuntimeError("Error getting package")

        logger.info_success("Package downloaded successfully")
        return package_name

    def install_package(
        self,
        package_name: str,
        command_template: str,
        client: paramiko.SSHClient | None = None,
        package_alias: str | None = None,
    ) -> None:
        """
        Installs a package (dependency or Wazuh component) on a remote machine using SSH.

        Args:
            package_name (str): The name of the package to install.
            command_template (str): The command template to use for installation.
            client (paramiko.SSHClient): The SSH client to use for executing the command.
            package_alias (str, optional): An alias for the package name used in logs. Defaults to None.

        Raises:
            Exception: If there is an error during the installation process.

        Returns:
            None
        """
        package_alias = package_alias or package_name
        logger.debug(f"Installing {package_alias}")

        output, error_output = exec_command(command=command_template.format(package_name=package_name), client=client)

        if "is already installed" in output:
            logger.debug(f"{package_alias} is already installed")
        elif "WARNING" in error_output:
            logger.warning(f"{error_output}")
            logger.info_success(f"{package_alias} installed successfully")
        elif not error_output:
            logger.info_success(f"{package_alias} installed successfully")
        else:
            logger.error(f"Error installing {package_alias}: {error_output}")
            raise RuntimeError(f"Error installing {package_alias}")
