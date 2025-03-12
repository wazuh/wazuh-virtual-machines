from enum import StrEnum


class ComponentConfigFile(StrEnum):
    WAZUH_SERVER = "/etc/wazuh-server/wazuh-server.yml"
    WAZUH_INDEXER = "/etc/wazuh-indexer/opensearch.yml"
    WAZUH_DASHBOARD = "/etc/wazuh-dashboard/opensearch_dashboards.yml"


class ComponentCertsDirectory(StrEnum):
    WAZUH_SERVER = "/etc/wazuh-server/certs"
    WAZUH_INDEXER = "/etc/wazuh-indexer/certs"
    WAZUH_DASHBOARD = "/etc/wazuh-dashboard/certs"


class ComponentCertsConfigParameter(StrEnum):
    # Wazuh Server
    WAZUH_SERVER_KEY = "server.node.ssl.key"
    WAZUH_SERVER_CERT = "server.node.ssl.cert"
    WAZUH_SERVER_CA = "server.node.ssl.ca"
    # Wazuh Indexer
    WAZUH_INDEXER_KEY = "plugins.security.ssl.http.pemkey_filepath"
    WAZUH_INDEXER_CERT = "plugins.security.ssl.http.pemcert_filepath"
    WAZUH_INDEXER_CA = "plugins.security.ssl.http.pemtrustedcas_filepath"
    # Wazuh Dashboard
    WAZUH_DASHBOARD_KEY = "server.ssl.key"
    WAZUH_DASHBOARD_CERT = "server.ssl.certificate"
    WAZUH_DASHBOARD_CA = "opensearch.ssl.certificateAuthorities"
