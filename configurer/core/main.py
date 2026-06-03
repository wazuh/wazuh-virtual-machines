from pathlib import Path

from configurer.core import CoreConfigurer
from models import Inventory

FILES_CONFIGURATION_NAME = "configuration_mappings.yaml"
FILES_CONFIGURATION_PATH = Path(__file__).parent / "static" / FILES_CONFIGURATION_NAME


def main(inventory_path: Path | None = None):
    """
    Main function to configure the core components and create their certificates using the provided inventory path.

    Args:
        inventory_path (Path | None): The path to the inventory file. If None, the configuration will be done locally.

    Returns:
        None
    """

    inventory = Inventory(inventory_path=inventory_path) if inventory_path else None
    CoreConfigurer(inventory=inventory, files_configuration_path=FILES_CONFIGURATION_PATH).configure()
