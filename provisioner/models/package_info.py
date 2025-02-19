from pydantic import AnyUrl, BaseModel
import pydantic_core
from provisioner.utils import Package_type, Component, Component_arch, AllowedUrlHost

from .utils import check_correct_url
from utils import Logger

logger = Logger("Package provision")

class PackageInfo(BaseModel):
    packages_url_content: dict
    package_type: Package_type = Package_type.RPM
    arch: Component_arch = Component_arch.X86_64
    
    @property
    def indexer_packages(self) -> dict:
        return self.get_component_packages(Component.WAZUH_INDEXER, self.package_type)
    
    @property
    def server_packages(self) -> dict:
        return self.get_component_packages(Component.WAZUH_SERVER, self.package_type)
    
    @property
    def dashboard_packages(self) -> dict:
        return self.get_component_packages(Component.WAZUH_DASHBOARD, self.package_type)
    
    def get_component_packages(self, component: Component, package_type: Package_type = package_type) -> dict:
        component_packages = self.packages_url_content.get(component)
        if component_packages is None:
            raise KeyError(f"Packages for {component} not found.")
        
        component_packages_by_type = component_packages.get(package_type)
        if component_packages_by_type is None:
            raise KeyError(f"Packages for {component} with {package_type} type not found.")
        
        return component_packages_by_type


    def get_package_by_arch(self, component: Component, package_type: Package_type = package_type, component_arch: Component_arch = arch) -> AnyUrl:
        logger.debug(f"Getting URL for {component} with {component_arch} architecture...")
        try:
            package_url = AnyUrl(self.get_component_packages(component, package_type=package_type).get(component_arch, None))
        except pydantic_core._pydantic_core.ValidationError:
            raise ValueError(f"URL for {component} with {component_arch} architecture has an invalid format.")

        if package_url is None:
            raise TypeError(f"Arch {component_arch} not found in {component} packages. Expected an URL but got None.")

        if not check_correct_url(package_url, [AllowedUrlHost.RELEASE, AllowedUrlHost.PRE_RELEASE, AllowedUrlHost.INTERNAL]):
            raise ValueError(f"URL for {component} with {component_arch} architecture is not for Wazuh packages.")

        return package_url
