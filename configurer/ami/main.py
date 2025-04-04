from pathlib import Path
from typing import Literal

from configurer.ami.ami_post_configurer import AmiPostCustomizer
from configurer.ami.ami_pre_configurer import AmiCustomizer, AmiLocalFilePath
from models import Inventory


def ami_pre_configurer(inventory: Inventory) -> str:
    """
    Function to customize an Amazon Machine Image (AMI) for Wazuh.
    This function initializes an `AmiCustomizer` object with the provided inventory
    and local file paths for Wazuh customization resources. It then performs the
    following operations:
    1. Creates a Wazuh user on the AMI.
    2. Applies customizations to the AMI:
       - Removes the default instance user (ec2-user)
       - Configures cloud-init settings for the Wazuh user
       - Updates the system hostname to 'wazuh-server'
       - Configures the MOTD (Message of The Day) with Wazuh branding
       - Stops journald log storage to prevent excessive logging
       - Creates and enables a service to automatically set Wazuh Indexer's JVM heap size
         based on available system RAM

    Args:
        inventory_path (Path): Path to the inventory file.

    Returns:
        str: The name of the Wazuh user created on the AMI.
    """
    
    ami_customizer = AmiCustomizer(
        inventory=inventory,
        wazuh_banner_path=Path(AmiLocalFilePath.WAZUH_BANNER_LOGO),
        local_set_ram_script_path=Path(AmiLocalFilePath.SET_RAM_SCRIPT),
        local_update_indexer_heap_service_path=Path(AmiLocalFilePath.UPDATE_INDEXER_HEAP_SERVICE),
        local_customize_certs_service_path=Path(AmiLocalFilePath.CUSTOMIZE_CERTS_SERVICE),
        local_customize_certs_timer_path=Path(AmiLocalFilePath.CUSTOMIZE_CERTS_TIMER),
    )

    wazuh_user = ami_customizer.create_wazuh_user()
    ami_customizer.customize()
    
    return wazuh_user
    

def ami_post_configurer(inventory: Inventory) -> None:
    ami_post_customizer = AmiPostCustomizer(inventory=inventory)
    ami_post_customizer.post_customize()
    
    return None


def main(inventory_path: Path, type: Literal["ami-pre-configurer", "ami-post-configurer"]) -> str | None:
    inventory = Inventory(inventory_path=inventory_path)

    if type == "ami-pre-configurer":
        return ami_pre_configurer(inventory=inventory)
    elif type == "ami-post-configurer":
        return ami_post_configurer(inventory=inventory)
    else:
        raise ValueError("Invalid type. Expected 'ami-pre-configurer' or 'ami-post-configurer'.")
