from enum import StrEnum, auto


class Component(StrEnum):
    WAZUH_INDEXER = auto()
    WAZUH_MANAGER = auto()
    WAZUH_DASHBOARD = auto()
    ALL = auto()


class PasswordToolComponent(StrEnum):
    PASSWORD_TOOL = "password-tool.sh"


class CertificatesComponent(StrEnum):
    CERTS_TOOL = "certs-tool.sh"
    CONFIG = "config.yml"


class RemoteDirectories(StrEnum):
    WAZUH_ROOT_DIR = "~/wazuh-configure"
    TOOLS_DIR = f"{WAZUH_ROOT_DIR}/tools"
    PACKAGES = f"{WAZUH_ROOT_DIR}/packages"
    CERTS = f"{TOOLS_DIR}/certs"
    PASSWORD_TOOL = f"{TOOLS_DIR}"
