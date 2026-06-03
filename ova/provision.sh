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
INSTALL_ARGS="-a"

check_services() {
    local retries
    local http_status

    echo "Checking wazuh-indexer"
    retries=0
    while true; do
        http_status=$(curl -XGET https://localhost:9200/ -uadmin:admin -k \
            --max-time 30 -s -o /dev/null -w "%{http_code}")
        [ "${http_status}" -eq 200 ] && break
        retries=$((retries + 1))
        if [ "${retries}" -ge 5 ]; then
            echo "ERROR: wazuh-indexer health check failed (HTTP ${http_status})"
            exit 1
        fi
        echo "wazuh-indexer not ready, retrying in 10s (${retries}/5)"
        sleep 10
    done
    echo "wazuh-indexer OK"

    echo "Checking wazuh-manager"
    if ! systemctl is-active --quiet wazuh-manager; then
        echo "ERROR: wazuh-manager is not active"
        systemctl status wazuh-manager || true
        exit 1
    fi
    echo "wazuh-manager OK"

    echo "Checking wazuh-dashboard"
    retries=0
    while true; do
        http_status=$(curl -XGET https://localhost:443/status -uadmin:admin -k \
            --max-time 30 -s -o /dev/null -w "%{http_code}")
        [ "${http_status}" -eq 200 ] && break
        retries=$((retries + 1))
        if [ "${retries}" -ge 20 ]; then
            echo "ERROR: wazuh-dashboard health check failed (HTTP ${http_status})"
            exit 1
        fi
        echo "wazuh-dashboard not ready, retrying in 15s (${retries}/20)"
        sleep 15
    done
    echo "wazuh-dashboard OK"

    echo "Checking filebeat"
    if filebeat test output 2>&1 | grep -qi "ERROR"; then
        echo "ERROR: filebeat test output reported errors"
        filebeat test output
        exit 1
    fi
    echo "filebeat OK"

    echo "All services healthy"
}

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

echo "Checking services health"
check_services

echo "Stopping Filebeat and Wazuh Manager"
systemctl stop filebeat wazuh-manager

# Delete indexes
echo "Deleting indexes"
for index in "${INDEXES[@]}"; do
    curl -u admin:admin -XDELETE "https://127.0.0.1:9200/$index" -k
done

# Recreate empty indexes (wazuh-alerts and wazuh-archives)
echo "Recreating empty indexes"
bash /usr/share/wazuh-indexer/bin/indexer-security-init.sh -ho 127.0.0.1 || {
    echo "ERROR: indexer security init failed"
    exit 1
}

echo "Stopping Wazuh indexer and Wazuh dashboard"
systemctl stop wazuh-indexer wazuh-dashboard
systemctl disable wazuh-manager
systemctl disable wazuh-dashboard

echo "Cleaning system"
clean
