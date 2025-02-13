#!/bin/bash

# Parameters
INSTALLATION_ASSISTANT_BRANCH=$1
WVM_BRANCH=$2
PACKAGES_REPOSITORY=$3
DEBUG=$4

echo "INSTALLATION_ASSISTANT_BRANCH: ${INSTALLATION_ASSISTANT_BRANCH}"
echo "WVM_BRANCH: ${WVM_BRANCH}"
echo "PACKAGES_REPOSITORY: ${PACKAGES_REPOSITORY}"
echo "DEBUG: ${DEBUG}"

# Execute the Python script via vagrant ssh
eval "python3 /tmp/workflow_assets/ova_configurer.py --wia_branch ${INSTALLATION_ASSISTANT_BRANCH} --wvm_branch ${WVM_BRANCH} --repository ${PACKAGES_REPOSITORY} --debug ${DEBUG}"
