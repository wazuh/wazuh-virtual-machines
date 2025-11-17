from pathlib import Path

import yaml
from pydantic import BaseModel

from models import Inventory
from provisioner.utils import Component_arch, Package_type
from utils import Component

from .certs_info import CertsInfo
from .components_dependencies import ComponentsDependencies
from .package_info import PackageInfo
from .password_tool_info import PasswordToolInfo
from .utils import format_certificates_urls_file, format_component_urls_file, format_password_tool_urls_file


class Input(BaseModel):
    """
    Input model representing the configuration for provisioning.

    Attributes:
        component (Component): The component to be provisioned.
        inventory_path (Path): Path to the inventory file.
        packages_url_path (Path): Path to the packages URL file.
        package_type (Package_type): Type of the package (default is RPM).
        arch (Component_arch): Architecture of the component (default is X86_64).
        dependencies_path (Path): Path to the dependencies file.

    Properties:
        dependencies (ComponentsDependencies): Parsed dependencies from the dependencies file.
        packages_url_content (PackageInfo): Parsed package information from the packages URL file.
        certificates_content (CertsInfo): Parsed certificate information from the packages URL file.
        inventory_content (Inventory): Inventory content for the given host name.
    """

    component: Component
    inventory_path: Path | None
    packages_url_path: Path
    package_type: Package_type = Package_type.RPM
    arch: Component_arch = Component_arch.X86_64
    dependencies_path: Path

    @property
    def dependencies(self) -> ComponentsDependencies:
        try:
            with open(self.dependencies_path) as f:
                return ComponentsDependencies(dependencies_content=yaml.safe_load(f))
        except FileNotFoundError as err:
            raise FileNotFoundError(f"Dependencies file not found at {self.dependencies_path}") from err

    @property
    def packages_url_content(self) -> PackageInfo:
        try:
            packages_data = format_component_urls_file(self.packages_url_path)
            return PackageInfo(
                packages_url_content=packages_data,
                package_type=self.package_type,
                arch=self.arch,
            )
        except FileNotFoundError as err:
            raise FileNotFoundError(f"Packages file not found at {self.packages_url_path}") from err

    @property
    def certificates_content(self) -> CertsInfo:
        try:
            certs_data = format_certificates_urls_file(self.packages_url_path)
            return CertsInfo(certs_url_content=certs_data)
        except FileNotFoundError as err:
            raise FileNotFoundError(f"Certificates file not found at {self.packages_url_path}") from err

    @property
    def password_tool_url(self) -> PasswordToolInfo:
        try:
            password_tool_data = format_password_tool_urls_file(self.packages_url_path)
            if password_tool_data is None:
                raise ValueError("Password tool URL not found in the packages URL file.")
            return PasswordToolInfo(password_tool_url=password_tool_data)
        except FileNotFoundError as err:
            raise FileNotFoundError(f"Password tool file not found at {self.packages_url_path}") from err

    @property
    def inventory_content(self, host_name: str | None = None) -> Inventory | None:
        return Inventory(self.inventory_path, host_name) if self.inventory_path else None
