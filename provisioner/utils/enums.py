from enum import StrEnum, auto

class AllowedUrlHost(StrEnum):
    RELEASE = "packages.wazuh.com"
    PRE_RELEASE = "packages-dev.wazuh.com"
    INTERNAL = "packages-dev.internal.wazuh.com"
    
class Package_manager(StrEnum):
    YUM = auto()
    APT = auto()

class Package_type(StrEnum):
    RPM = "rpm"
    DEB = "deb"

class Component(StrEnum):
    WAZUH_INDEXER = auto()
    WAZUH_SERVER = auto()
    WAZUH_DASHBOARD = auto()
    ALL = auto()

class Component_arch(StrEnum):
    AMD64 = auto()
    X86_64 = auto()
    ARM64 = auto()
    AARCH64 = auto()
    
class CertificatesComponent(StrEnum):
    CERTS_TOOL = auto()
    CONFIG = auto()

class RemoteDirectories(StrEnum):
    WAZUH_ROOT_DIR = "~/wazuh-ami-configure"
    PACKAGES = f"{WAZUH_ROOT_DIR}/packages"
    CERTS = f"{WAZUH_ROOT_DIR}/certs"