from typing import List

from pydantic import BaseModel

from provisioner.utils import Component, Package_manager, Package_type


class ComponentsDependencies(BaseModel):
    dependencies_content: dict
    package_type: Package_type = Package_type.RPM
    
    @property
    def package_manager(self) -> Package_manager:
        if self.package_type == Package_type.RPM:
            return Package_manager.YUM
        return Package_manager.APT
    
    @property
    def indexer_dependencies(self) -> List[str]:
        return self.get_component_dependencies(Component.WAZUH_INDEXER)
    
    @property
    def server_dependencies(self) -> List[str]:
        return self.get_component_dependencies(Component.WAZUH_SERVER)
    
    @property
    def dashboard_dependencies(self) -> List[str]:
        return self.get_component_dependencies(Component.WAZUH_DASHBOARD)
    
    def get_component_dependencies(self, component: Component) -> List[str]:
        if self.dependencies_content.get(component) is None:
            raise KeyError(f"Dependencies for {component.name} not found")
        
        return self.dependencies_content.get(component, {}).get(self.package_manager, [])
