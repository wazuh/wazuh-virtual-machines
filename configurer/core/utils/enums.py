from enum import StrEnum


class ComponentConfigFile(StrEnum):
    WAZUH_MANAGER = "/var/wazuh-manager/etc/ossec.conf"
    WAZUH_INDEXER = "/etc/wazuh-indexer/opensearch.yml"
    WAZUH_DASHBOARD = "/etc/wazuh-dashboard/opensearch_dashboards.yml"


class ComponentCertsDirectory(StrEnum):
    WAZUH_MANAGER = "/var/wazuh-manager/etc/certs"
    WAZUH_INDEXER = "/etc/wazuh-indexer/certs"
    WAZUH_DASHBOARD = "/etc/wazuh-dashboard/certs"


class ComponentCertsConfigParameter(StrEnum):
    # Wazuh Server
    # We use ossec_config[0] because there is more than one ossec_config entry in the ossec.conf file and need to
    # identify the correct one.
    # This siyntax is needed for yq to correctly identify the path to modify.
    WAZUH_MANAGER_KEY = "ossec_config[0].indexer.ssl.key"
    WAZUH_MANAGER_CERT = "ossec_config[0].indexer.ssl.certificate"
    WAZUH_MANAGER_CA = "ossec_config[0].indexer.ssl.certificate_authorities.ca"
    # Wazuh Indexer
    WAZUH_INDEXER_KEY = "plugins.security.ssl.http.pemkey_filepath"
    WAZUH_INDEXER_CERT = "plugins.security.ssl.http.pemcert_filepath"
    WAZUH_INDEXER_CA = "plugins.security.ssl.http.pemtrustedcas_filepath"
    # Wazuh Dashboard
    WAZUH_DASHBOARD_KEY = "server.ssl.key"
    WAZUH_DASHBOARD_CERT = "server.ssl.certificate"
    WAZUH_DASHBOARD_CA = "opensearch.ssl.certificateAuthorities"
