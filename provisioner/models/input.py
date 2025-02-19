from pathlib import Path
from pydantic import BaseModel
from .certs_info import CertsInfo
from .components_dependencies import ComponentsDependencies
from .inventory import Inventory
from .package_info import PackageInfo
from provisioner.utils import Component, Package_type, Component_arch

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
            with open(self.packages_url_path, "r") as f:
                data = yaml.safe_load(f) or {}
                data.pop("certificates", None)
                return PackageInfo(packages_url_content=data, package_type=self.package_type, arch=self.arch)
        except FileNotFoundError:
            raise FileNotFoundError(f"Dependencies file not found at {self.packages_url_path}")
    
    @property
    def certificates_content(self) -> CertsInfo:
        """Retorna solo la sección 'certificates' del YAML"""
        try:
            with open(self.packages_url_path, "r") as f:
                data = yaml.safe_load(f) or {}
                return CertsInfo(certs_url_content=data.get("certificates", {}))
        except FileNotFoundError:
            raise FileNotFoundError(f"Dependencies file not found at {self.packages_url_path}")
    
    @property
    def inventory_content(self, host_name: str | None = None) -> Inventory:
        return Inventory(self.inventory_path, host_name)
