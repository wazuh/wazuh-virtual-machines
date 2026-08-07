import argparse
from pathlib import Path

from configurer.ami import ami_configurer_main
from configurer.core import core_configurer_main
from configurer.ova.ova_post_configurer import ova_post_configurer_main
from configurer.ova.ova_pre_configurer import ova_pre_configurer_main
from generic import change_inventory_user
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
        --component (str): Component to provision (optional, default: "all", choices: ["wazuh_indexer", "wazuh_manager", "wazuh_dashboard", "wazuh_agent", "all"]).
        --execute (str): Module to execute (required, choices: ["provisioner", "core-configurer", "ova-pre-configurer", "ova-post-configurer", "ami-pre-configurer", "ami-post-configurer", "all-ami"]).
    """
    parser = argparse.ArgumentParser(description="Component Provisioner")
    parser.add_argument("--inventory", required=False, help="Path to the inventory file")
    parser.add_argument("--packages-url-path", required=False, help="Path to the packages URL file")
    parser.add_argument("--package-type", required=False, default="rpm", choices=["rpm", "deb"])
    parser.add_argument(
        "--execute",
        required=True,
        choices=[
            "provisioner",
            "core-configurer",
            "ova-pre-configurer",
            "ova-post-configurer",
            "ami-pre-configurer",
            "ami-post-configurer",
            "all-ami",
        ],
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
        choices=["wazuh_indexer", "wazuh_manager", "wazuh_dashboard", "wazuh_agent", "all"],
        help="Component to provision",
    )

    return parser.parse_args()


def check_required_arguments(parsed_args):
    if parsed_args.execute in ["provisioner", "all-ami", "ova-post-configurer"] and not parsed_args.packages_url_path:
        raise ValueError(
            '--packages-url-path is required for the "provisioner", "all-ami" and "ova-post-configurer" --execute value'
        )

    if parsed_args.execute in ["ami-pre-configurer", "ami-post-configurer", "all-ami"] and not parsed_args.inventory:
        raise ValueError(
            '--inventory is required for the "ami-pre-configurer", "ami-post-configurer" and "all-ami" --execute value'
        )


def main():
    """
    Main entry point for the script.

    This function parses the command-line arguments and executes the appropriate
    subcommands based on the `--execute` argument. It supports the following
    subcommands:
    - `provisioner`: Executes the provisioner logic, which requires the
        `--packages-url-path` argument along with other optional arguments.
    - `configurer`: Executes the core configurer logic.
    - `ami-pre-configurer`: Executes the AMI pre-configurer logic, which requires
        the `--inventory` argument.
    - `ami-post-configurer`: Executes the AMI post-configurer logic, which requires
        the `--inventory` and `--packages-url-path` arguments
    - `all-ami`: Executes both the AMI pre-configurer and post-configurer logic,
        which requires the `--inventory` and `--packages-url-path` arguments.
    The script also validates the required arguments based on the selected subcommand.
    """

    parsed_args = parse_arguments()
    check_required_arguments(parsed_args)

    if parsed_args.execute == "ova-pre-configurer":
        ova_pre_configurer_main()

    if parsed_args.execute in ["ami-pre-configurer", "all-ami"]:
        new_user = ami_configurer_main(inventory_path=parsed_args.inventory, type="ami-pre-configurer")
        if not new_user:
            raise ValueError("ami-pre-configurer did not return a new user")
        change_inventory_user(inventory_path=parsed_args.inventory, new_user=new_user)

    if parsed_args.execute in ["provisioner", "ova-post-configurer", "all-ami"]:
        provisioner_main(
            packages_url_path=Path(parsed_args.packages_url_path),
            package_type=parsed_args.package_type,
            arch=parsed_args.arch,
            dependencies=Path(parsed_args.dependencies),
            component=parsed_args.component,
            inventory=parsed_args.inventory,
        )

    if parsed_args.execute in ["core-configurer", "ova-post-configurer", "all-ami"]:
        core_configurer_main(inventory_path=parsed_args.inventory)

    if parsed_args.execute == "ova-post-configurer":
        ova_post_configurer_main()

    if parsed_args.execute in ["ami-post-configurer", "all-ami"]:
        ami_configurer_main(inventory_path=parsed_args.inventory, type="ami-post-configurer")


if __name__ == "__main__":
    main()
