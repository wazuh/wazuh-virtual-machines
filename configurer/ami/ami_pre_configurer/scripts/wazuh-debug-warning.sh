#!/usr/bin/env bash

# Only interactive shells
[[ $- != *i* ]] && return

FLAG="/var/lib/wazuh/DEBUG_MODE"
[[ ! -f "$FLAG" ]] && return

printf '\033[1;31m'
printf '%s\n' '=========================================='
printf '%s\n' 'WARNING: WAZUH AMI IN DEBUG MODE'
printf '%s\n' '=========================================='
printf '%s\n' 'The Wazuh AMI started in debug mode.'
printf '%s\n' 'Some services may not be ready yet.'
printf '%s\n' 'Please check the logs for more information.'
printf '%s\n' '/var/log/wazuh-ami-customizer.log'
printf '%s\n' '=========================================='
printf '\033[0m\n'

