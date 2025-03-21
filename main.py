import argparse
from pathlib import Path

from configurer.core import core_configurer_main
from provisioner import provisioner_main

DEPENDENCIES_FILE_NAME = "wazuh_dependencies.yaml"
DEPENDENCIES_FILE_PATH = Path("provisioner") / "static" / DEPENDENCIES_FILE_NAME


def parse_arguments():
    """
    Parse command-line arguments for the Provisioner and Configurer.

    Returns:
        argparse.Namespace: Parsed command-line arguments.

    Arguments:
        --inventory (str): Path to the inventory file (optional).
        --packages-url-path (str): Path to the packages URL file (required if the provisioner module will be executed).
        --package-type (str): Type of package to provision (optional, default: "rpm", choices: ["rpm", "deb"]).
        --arch (str): Architecture type (optional, default: "x86_64", choices: ["x86_64", "amd64", "arm64", "aarch64"]).
        --dependencies (str): Path to the dependencies file (optional, default: DEPENDENCIES_FILE_PATH).
        --component (str): Component to provision (optional, default: "all", choices: ["wazuh_indexer", "wazuh_server", "wazuh_dashboard", "all"]).
        --execute (str): Module to execute (optional, default: "all", choices: ["provisioner", "configurer", "all"]).
    """
    parser = argparse.ArgumentParser(description="Component Provisioner")
    parser.add_argument("--inventory", required=False, help="Path to the inventory file")
    parser.add_argument("--packages-url-path", required=False, help="Path to the packages URL file")
    parser.add_argument("--package-type", required=False, default="rpm", choices=["rpm", "deb"])
    parser.add_argument("--execute", required=False, default="all", choices=["provisioner", "configurer", "all"])
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


def main():
    """
    Main entry point for the script.

    This function parses the command-line arguments and executes the appropriate
    subcommands based on the `--execute` argument. It supports the following
    subcommands:
    - `provisioner`: Executes the provisioner logic, which requires the
        `--packages-url-path` argument along with other optional arguments.
    - `configurer`: Executes the core configurer logic.
    - `all`: Executes both the provisioner and configurer logic.

    Raises:
            ValueError: If the `--packages-url-path` argument is missing when the
            `provisioner` or `all` subcommand is executed.
    """

    parsed_args = parse_arguments()

    if parsed_args.execute in ["provisioner", "all"]:
        if not parsed_args.packages_url_path:
            raise ValueError("Missing required argument --packages-url-path")

        provisioner_main(
            packages_url_path=Path(parsed_args.packages_url_path),
            package_type=parsed_args.package_type,
            arch=parsed_args.arch,
            dependencies=Path(parsed_args.dependencies),
            component=parsed_args.component,
            inventory=parsed_args.inventory,
        )
    if parsed_args.execute in ["configurer", "all"]:
        core_configurer_main(inventory_path=parsed_args.inventory)


if __name__ == "__main__":
    main()
