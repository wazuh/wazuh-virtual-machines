#!/bin/bash

PACKAGES_REPOSITORY=$1
DEBUG=$2

INSTALLER="/tmp/wazuh-install.sh"
SYSTEM_USER="wazuh-user"
HOSTNAME="wazuh-server"
INDEXES=("wazuh-alerts-*" "wazuh-archives-*" "wazuh-states-*" "wazuh-statistics-*" "wazuh-monitoring-*")

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ASSETS_PATH="${CURRENT_PATH}/assets"
CUSTOM_PATH="${ASSETS_PATH}/custom"
INSTALL_ARGS="-a --install-dependencies"

if [[ "${PACKAGES_REPOSITORY}" == "dev" ]]; then
  INSTALL_ARGS+=" -d pre-release"
elif [[ "${PACKAGES_REPOSITORY}" == "staging" ]]; then
  INSTALL_ARGS+=" -d staging"
fi

if [[ "${DEBUG}" = "yes" ]]; then
  INSTALL_ARGS+=" -v"
fi

echo "Using ${PACKAGES_REPOSITORY} packages"

. ${ASSETS_PATH}/steps.sh

WAZUH_VERSION=$(cat ${INSTALLER} | grep "wazuh_version=" | cut -d "\"" -f 2)

# System configuration
echo "Configuring system"
systemConfig

# Edit installation script
echo "Editing installation script"
preInstall

# Install
echo "Installing Wazuh central components"
bash ${INSTALLER} ${INSTALL_ARGS}

echo "Stopping Filebeat and Wazuh Manager"
systemctl stop filebeat wazuh-manager

# Delete indexes
echo "Deleting indexes"
for index in "${INDEXES[@]}"; do
    curl -u admin:admin -XDELETE "https://127.0.0.1:9200/$index" -k
done

# Recreate empty indexes (wazuh-alerts and wazuh-archives)
echo "Recreating empty indexes"
bash /usr/share/wazuh-indexer/bin/indexer-security-init.sh -ho 127.0.0.1

echo "Stopping Wazuh indexer and Wazuh dashboard"
systemctl stop wazuh-indexer wazuh-dashboard
systemctl disable wazuh-manager
systemctl disable wazuh-dashboard

echo "Cleaning system"
clean
