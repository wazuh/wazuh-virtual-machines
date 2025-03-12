from enum import StrEnum, auto


class Component(StrEnum):
    WAZUH_INDEXER = auto()
    WAZUH_SERVER = auto()
    WAZUH_DASHBOARD = auto()
    ALL = auto()


class CertificatesComponent(StrEnum):
    CERTS_TOOL = "certs-tool.sh"
    CONFIG = "config.yml"


class RemoteDirectories(StrEnum):
    WAZUH_ROOT_DIR = "~/wazuh-configure"
    PACKAGES = f"{WAZUH_ROOT_DIR}/packages"
    CERTS = f"{WAZUH_ROOT_DIR}/certs"
