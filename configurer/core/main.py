from pathlib import Path

from configurer.core import CoreConfigurer
from models import Inventory

FILES_CONFIGURATION_NAME = "configuration_mappings.yaml"
FILES_CONFIGURATION_PATH = Path(__file__).parent / "static" / FILES_CONFIGURATION_NAME


def main(inventory_path: Path):
    inventory = Inventory(inventory_path=inventory_path)
    CoreConfigurer(inventory=inventory, files_configuration_path=FILES_CONFIGURATION_PATH).configure()
