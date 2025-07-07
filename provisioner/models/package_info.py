import pydantic_core
from pydantic import AnyUrl, BaseModel

from provisioner.utils import AllowedUrlHost, Component_arch, Package_type
from utils import Component, Logger

from .utils import check_correct_url

logger = Logger("Package provision")


class PackageInfo(BaseModel):
    """
    PackageInfo class represents the information about the main packages for Wazuh (indexer, server and dashboard).

    Attributes:
        packages_url_content (dict): Dictionary containing URLs for different packages.
        package_type (Package_type): Type of the package, default is RPM.
        arch (Component_arch): Architecture of the component, default is X86_64.

    Properties:
        indexer_packages (dict): Returns the packages for Wazuh Indexer component.
        server_packages (dict): Returns the packages for Wazuh Server component.
        dashboard_packages (dict): Returns the packages for Wazuh Dashboard component.
    """

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
        """
        Retrieve packages for a specific component and package type.

        Args:
            component (Component): The component for which to retrieve packages.
            package_type (Package_type, optional): The type of packages to retrieve. Defaults to package_type.

        Returns:
            dict: A dictionary containing the packages for the specified component and package type.

        Raises:
            KeyError: If the packages for the specified component or package type are not found.
        """
        component_packages = self.packages_url_content.get(component)
        logger.debug(f"Using component_packages {component_packages}...")
        if component_packages is None:
            raise KeyError(f"Packages for {component} not found.")

        component_packages_by_type = component_packages.get(package_type)
        if component_packages_by_type is None:
            raise KeyError(f"Packages for {component} with {package_type} type not found.")

        return component_packages_by_type

    def get_package_by_arch(
        self,
        component: Component,
        package_type: Package_type = package_type,
        component_arch: Component_arch = arch,
    ) -> AnyUrl:
        """
        Retrieve the package URL for a given component and architecture.

        Args:
            component (Component): The component for which the package URL is needed.
            package_type (Package_type, optional): The type of the package. Defaults to package_type.
            component_arch (Component_arch, optional): The architecture of the component. Defaults to arch.

        Returns:
            AnyUrl: The URL of the package for the specified component and architecture.

        Raises:
            ValueError: If the URL format is invalid or if the URL is not for Wazuh packages.
            TypeError: If the architecture is not found in the component packages.
        """
        logger.debug(f"Getting URL for {component} with {component_arch} architecture...")

        package_url = self.get_component_packages(component, package_type=package_type).get(component_arch, None)
        if package_url is None:
            raise ValueError(f"Arch {component_arch} not found in {component} packages. Expected an URL but got None.")

        logger.debug(f"Using package_url {package_url}...")

        try:
            package_url = AnyUrl(package_url)
        except pydantic_core._pydantic_core.ValidationError as err:
            raise ValueError(f"URL for {component} with {component_arch} architecture has an invalid format.") from err

        if not check_correct_url(
            package_url,
            [allowed_url.value for allowed_url in AllowedUrlHost],
        ):
            raise ValueError(f"URL for {component} with {component_arch} architecture is not for Wazuh packages.")

        return package_url
