from enum import StrEnum, auto


class Component(StrEnum):
    WAZUH_INDEXER = auto()
    WAZUH_MANAGER = auto()
    WAZUH_DASHBOARD = auto()
    WAZUH_AGENT = auto()
    ALL = auto()


class RemoteDirectories(StrEnum):
    WAZUH_ROOT_DIR = "~/wazuh-configure"
    PACKAGES = f"{WAZUH_ROOT_DIR}/packages"
