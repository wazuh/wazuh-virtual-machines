import os
from enum import StrEnum
from pathlib import Path


class AmiLocalFilePath(StrEnum):
    WAZUH_BANNER_LOGO = str(
        Path(os.getcwd()) / "configurer" / "ami" / "ami_pre_configurer" / "static" / "80-wazuh-banner"
    )
    SET_RAM_SCRIPT = str(Path(os.getcwd()) / "utils" / "scripts" / "automatic_set_ram.sh")
    UPDATE_INDEXER_HEAP_SERVICE = str(Path(os.getcwd()) / "utils" / "scripts" / "updateIndexerHeap.service")
    CUSTOMIZE_CERTS_SERVICE = str(
        Path(os.getcwd()) / "configurer" / "ami" / "ami_pre_configurer" / "scripts" / "wazuh-ami-customizer.service"
    )
    CUSTOMIZE_CERTS_TIMER = str(
        Path(os.getcwd()) / "configurer" / "ami" / "ami_pre_configurer" / "scripts" / "wazuh-ami-customizer.timer"
    )
