from typing import List

from pydantic import BaseModel

from provisioner.utils import Component, Package_manager, Package_type


class ComponentsDependencies(BaseModel):
    """
    ComponentsDependencies is a model that manages the dependencies for different Wazuh components
    based on the package type (rpm or apt).

    Attributes:
        dependencies_content (dict): A dictionary containing the dependencies for various components.
        package_type (Package_type): The type of package manager to use (default is RPM).

    Properties:
        package_manager (Package_manager): Returns the appropriate package manager (YUM for rpm, APT for deb).
        indexer_dependencies (List[str]): Returns the dependencies for the Wazuh Indexer component.
        server_dependencies (List[str]): Returns the dependencies for the Wazuh Server component.
        dashboard_dependencies (List[str]): Returns the dependencies for the Wazuh Dashboard component.
    """
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
        """
        Retrieve the list of dependencies for a given component.

        Args:
            component (Component): The component for which to retrieve dependencies.

        Returns:
            List[str]: A list of dependencies for the specified component.

        Raises:
            KeyError: If the dependencies for the given component are not found.
        """
        if self.dependencies_content.get(component) is None:
            raise KeyError(f"Dependencies for {component} not found")

        return self.dependencies_content.get(component, {}).get(self.package_manager, [])
