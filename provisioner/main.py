import argparse
from pathlib import Path
from typing import List

from .models import ComponentInfo, Input
from .provisioner import Provisioner
from .utils import Component

DEPENDENCIES_FILE_NAME = "wazuh_dependencies.yaml"
DEPENDENCIES_FILE_PATH = Path(__file__).parent / "static" / DEPENDENCIES_FILE_NAME


def parse_arguments():
    parser = argparse.ArgumentParser(description="Component Provisioner")
    parser.add_argument("--inventory", required=True, help="Path to the inventory file")
    parser.add_argument(
        "--packages-url-path", required=True, help="Path to the packages URL file"
    )
    parser.add_argument(
        "--package-type", required=False, default="rpm", choices=["rpm", "deb"]
    )
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
    if input.component == Component.ALL:
        return [
            get_component_info(input, component)
            for component in Component
            if component != Component.ALL
        ]

    return [get_component_info(input, input.component)]


def main():
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
