#!/bin/bash

PACKAGES_REPOSITORY=$1
DEBUG=$2

INSTALLER="/tmp/wazuh-install.sh"
SYSTEM_USER="wazuh-user"
HOSTNAME="wazuh-server"
INDEXES=("wazuh-alerts-*" "wazuh-archives-*" "wazuh-states-vulnerabilities-*" "wazuh-statistics-*" "wazuh-monitoring-*")

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ASSETS_PATH="${CURRENT_PATH}/assets"
CUSTOM_PATH="${ASSETS_PATH}/custom"
INSTALL_ARGS="-a"

if [[ "${DEBUG}" = "yes" ]]; then
  INSTALL_ARGS+=" -v"
fi

echo "Using ${PACKAGES_REPOSITORY} packages"

. ${ASSETS_PATH}/steps.sh

WAZUH_VERSION=$(cat ${INSTALLER} | grep "wazuh_version=" | cut -d "\"" -f 2)

# System configuration
systemConfig

# Edit installation script
preInstall

# Install
bash ${INSTALLER} ${INSTALL_ARGS}

systemctl stop filebeat wazuh-manager

# Delete indexes
for index in "${INDEXES[@]}"; do
    curl -u admin:admin -XDELETE "https://127.0.0.1:9200/$index" -k
done

# Recreate empty indexes (wazuh-alerts and wazuh-archives)
bash /usr/share/wazuh-indexer/bin/indexer-security-init.sh -ho 127.0.0.1

systemctl stop wazuh-indexer wazuh-dashboard
systemctl enable wazuh-manager


clean