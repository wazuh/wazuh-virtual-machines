import argparse
from pathlib import Path
from typing import List

from .models import ComponentInfo, Input
from .provisioner import Provisioner
from .utils import Component

DEPENDENCIES_FILE_NAME = "wazuh_dependencies.yaml"
DEPENDENCIES_FILE_PATH = Path(__file__).parent / "static" / DEPENDENCIES_FILE_NAME


def parse_arguments():
    """
    Parse command-line arguments for the Component Provisioner.

    Returns:
        argparse.Namespace: Parsed command-line arguments.

    Arguments:
        --inventory (str): Path to the inventory file (required).
        --packages-url-path (str): Path to the packages URL file (required).
        --package-type (str): Type of package to provision (optional, default: "rpm", choices: ["rpm", "deb"]).
        --arch (str): Architecture type (optional, default: "x86_64", choices: ["x86_64", "amd64", "arm64", "aarch64"]).
        --dependencies (str): Path to the dependencies file (optional, default: DEPENDENCIES_FILE_PATH).
        --component (str): Component to provision (optional, default: "all", choices: ["wazuh_indexer", "wazuh_server", "wazuh_dashboard", "all"]).
    """
    parser = argparse.ArgumentParser(description="Component Provisioner")
    parser.add_argument("--inventory", required=False, help="Path to the inventory file")
    parser.add_argument("--packages-url-path", required=True, help="Path to the packages URL file")
    parser.add_argument("--package-type", required=False, default="rpm", choices=["rpm", "deb"])
    parser.add_argument(
        "--arch",
        required=False,
        default="x86_64",
        choices=["x86_64", "amd64", "arm64", "aarch64"],
    )
    parser.add_argument(
        "--dependencies",
        required=False,
        default=DEPENDENCIES_FILE_PATH,
        help="Path to the dependencies file",
    )
    parser.add_argument(
        "--component",
        required=False,
        default="all",
        choices=["wazuh_indexer", "wazuh_server", "wazuh_dashboard", "all"],
        help="Component to provision",
    )

    return parser.parse_args()


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


def parse_componets(input: Input) -> List[ComponentInfo]:
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


def main():
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
    parsed_args = parse_arguments()
    input = Input(
        component=parsed_args.component,
        inventory_path=parsed_args.inventory,
        packages_url_path=parsed_args.packages_url_path,
        package_type=parsed_args.package_type,
        arch=parsed_args.arch,
        dependencies_path=parsed_args.dependencies,
    )

    components = parse_componets(input)

    Provisioner(
        inventory=input.inventory_content,
        certs=input.certificates_content,
        components=components,
        arch=input.arch,
        package_type=input.package_type,
    ).provision()


if __name__ == "__main__":
    main()
