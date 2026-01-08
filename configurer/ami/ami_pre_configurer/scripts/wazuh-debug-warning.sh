#!/bin/bash

# Only interactive shells
[[ $- != *i* ]] && return

FLAG="/var/lib/wazuh/DEBUG_MODE"
[[ ! -f "$FLAG" ]] && return

RED="\033[1;31m"
NC="\033[0m"

cat <<EOF
${RED}
==========================================
WARNING: WAZUH AMI IN DEBUG MODE
==========================================
The Wazuh AMI started in debug mode.
Some services may not be ready yet.
Please check the logs for more information.
/var/log/wazuh-ami-customizer.log
==========================================
${NC}
EOF
