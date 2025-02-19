from pathlib import Path
from pydantic import BaseModel
from .certs_info import CertsInfo
from .components_dependencies import ComponentsDependencies
from .inventory import Inventory
from .package_info import PackageInfo
from provisioner.utils import Component, Package_type, Component_arch
from .utils import format_certificates_urls_file, format_component_urls_file
import yaml

class Input(BaseModel):
    component: Component
    inventory_path: Path
    packages_url_path: Path
    package_type: Package_type = Package_type.RPM
    arch: Component_arch = Component_arch.X86_64
    dependencies_path: Path

    @property
    def dependencies(self) -> ComponentsDependencies:
        try:
            with open(self.dependencies_path, "r") as f:
                return ComponentsDependencies(dependencies_content=yaml.safe_load(f))
        except FileNotFoundError:
            raise FileNotFoundError(f"Dependencies file not found at {self.dependencies_path}")
        
    @property
    def packages_url_content(self) -> PackageInfo:
        try:
            packages_data = format_component_urls_file(self.packages_url_path)
            return PackageInfo(packages_url_content=packages_data, package_type=self.package_type, arch=self.arch)
        except FileNotFoundError:
            raise FileNotFoundError(f"Packages file not found at {self.packages_url_path}")
    
    @property
    def certificates_content(self) -> CertsInfo:
        try:
            certs_data = format_certificates_urls_file(self.packages_url_path)
            return CertsInfo(certs_url_content=certs_data)
        except FileNotFoundError:
            raise FileNotFoundError(f"Certificates file not found at {self.packages_url_path}")
    
    @property
    def inventory_content(self, host_name: str | None = None) -> Inventory:
        return Inventory(self.inventory_path, host_name)
