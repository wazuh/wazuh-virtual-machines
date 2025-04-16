from pathlib import Path

from provisioner.utils.enums import Component_arch, Package_type
from utils import Component

from .models import ComponentInfo, Input
from .provisioner import Provisioner


def get_component_info(input: Input, component: Component) -> ComponentInfo:
    """
    Retrieve information about a specific component.

    Args:
        input (Input): An instance containing the necessary input data, such as package URLs and dependencies.
        component (Component): The component for which information is being retrieved.

    Returns:
        ComponentInfo: An object containing the name of the component, the package URL, and its dependencies.
    """
    return ComponentInfo(
        name=component,
        package_url=input.packages_url_content.get_package_by_arch(
            component=component,
            package_type=input.package_type,
            component_arch=input.arch,
        ),
        dependencies=input.dependencies.get_component_dependencies(component=component),
    )


def parse_componets(input: Input) -> list[ComponentInfo]:
    """
    Parse the components from the given input.

    Args:
        input (Input): The input object containing the component information.

    Returns:
        List[ComponentInfo]: A list of ComponentInfo objects based on the input component.
                             If the input component is Component.ALL, it returns a list of
                             ComponentInfo for all components except Component.ALL.
                             Otherwise, it returns a list with a single ComponentInfo for
                             the specified component.
    """
    if input.component == Component.ALL:
        return [get_component_info(input, component) for component in Component if component != Component.ALL]

    return [get_component_info(input, input.component)]


def main(
    packages_url_path: Path,
    component: Component,
    package_type: Package_type,
    arch: Component_arch,
    dependencies: Path,
    inventory: Path | None = None,
):
    """
    Main function to parse arguments, create an Input object, parse components, and provision the environment.

    This function performs the following steps:
    1. Parses command-line arguments.
    2. Creates an Input object with the parsed arguments.
    3. Parses components based on the input.
    4. Creates a Provisioner object and calls its provision method to set up the environment.

    The Input object includes:
    - component: The component to be provisioned.
    - inventory_path: Path to the inventory file.
    - packages_url_path: URL path to the packages.
    - package_type: Type of the package.
    - arch: Architecture type.
    - dependencies_path: Path to the dependencies file.

    The Provisioner object is initialized with:
    - inventory: Content of the inventory.
    - certs: Content of the certificates.
    - components: Parsed components.
    - arch: Architecture type.
    - package_type: Type of the package.
    """
    input = Input(
        component=component,
        inventory_path=inventory,
        packages_url_path=packages_url_path,
        package_type=package_type,
        arch=arch,
        dependencies_path=dependencies,
    )

    components = parse_componets(input)

    Provisioner(
        inventory=input.inventory_content,
        certs=input.certificates_content,
        components=components,
        arch=input.arch,
        package_type=input.package_type,
    ).provision()
