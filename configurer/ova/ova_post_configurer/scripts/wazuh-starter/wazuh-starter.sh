#!/bin/bash
# This script is used to configure the Wazuh environment after the installation

# Variables
logfile="/var/log/wazuh-starter.log"
debug="| tee -a ${logfile}"

# The Wazuh manager generates a random Authd registration password on startup and persists it in
# this file. The same password must be distributed to the agent so it can enroll against the manager.
wazuh_manager_authd_pass="/var/wazuh-manager/etc/authd.pass"
wazuh_agent_authd_pass="/var/ossec/etc/authd.pass"
authd_pass_max_retries=12
authd_pass_wait_time=5

###########################################
# Utility Functions
###########################################
function logger(){
  now=$(date +'%d/%m/%Y %H:%M:%S')
  mtype="INFO:"
  if [ -n "${1}" ]; then
      while [ -n "${1}" ]; do
          case ${1} in
              "-e")
                  mtype="ERROR:"
                  shift 1
                  ;;
              "-w")
                  mtype="WARNING:"
                  shift 1
                  ;;
              *)
                  message="${1}"
                  shift 1
                  ;;
          esac
      done
  fi
  printf "%s\n" "${now} ${mtype} ${message}" | tee -a "${logfile}"
}


###########################################
# Configuration Functions
###########################################

function starter_service() {
  logger "Starting $1 service"
  systemctl start $1
}

function verify_indexer() {
  logger "Waiting for Wazuh indexer to be ready"
  indexer_security_admin_comm="curl -XGET https://localhost:9200/ -uwazuh-admin:wazuh-admin -k --max-time 120 --silent -w \"%{http_code}\" --output /dev/null"
  http_status=$(eval "${indexer_security_admin_comm}")
  retries=0
  max_retries=5
  while [ "${http_status}" -ne 200 ]; do
      logger -w "Wazuh indexer is not ready yet, waiting 5 seconds"
      sleep 5
      retries=$((retries+1))
      if [ "${retries}" -eq "${max_retries}" ]; then
          logger -e "Wazuh indexer is not ready yet, trying to configure it again"
          configure_indexer
      fi
      http_status=$(eval "${indexer_security_admin_comm}")
  done
}

function verify_dashboard() {
  logger "Waiting for Wazuh dashboard to be ready"
  dashboard_check_comm="curl -XGET https://localhost:443/status -uwazuh-admin:wazuh-admin -k -w \"%{http_code}\" -s -o /dev/null"
  http_code=$(eval "${dashboard_check_comm}")
  retries=0
  max_dashboard_initialize_retries=20
  while [ "${http_code}" -ne "200" ];do
      logger -w "Wazuh dashboard is not ready yet, waiting 15 seconds"
      retries=$((retries+1))
      sleep 15
      if [ "${retries}" -eq "${max_dashboard_initialize_retries}" ]; then
          logger -e "Wazuh dashboard is not ready yet, trying to configure it again"
          configure_dashboard
      fi
      http_code=$(eval "${dashboard_check_comm}")
  done
}

function rotate_authd_password() {
  # Remove the Authd registration password baked into the image so the manager generates a new,
  # unique one when it starts. Otherwise every deployed VM would share the same password.
  logger "Removing pre-generated Authd registration password to force a new one on first boot"
  rm -f "${wazuh_manager_authd_pass}" "${wazuh_agent_authd_pass}"
}

function set_authd_password() {
  # Copy the password the manager generated on startup to the agent so it can enroll.
  logger "Setting the Wazuh agent registration password from the manager Authd password"
  retries=0
  while [ ! -f "${wazuh_manager_authd_pass}" ] && [ "${retries}" -lt "${authd_pass_max_retries}" ]; do
      logger -w "Manager Authd password file not ready yet, waiting ${authd_pass_wait_time} seconds"
      sleep "${authd_pass_wait_time}"
      retries=$((retries+1))
  done
  if [ ! -f "${wazuh_manager_authd_pass}" ]; then
      logger -e "Wazuh manager Authd password file not found at ${wazuh_manager_authd_pass}"
      exit 1
  fi
  cp "${wazuh_manager_authd_pass}" "${wazuh_agent_authd_pass}"
  chown root:wazuh "${wazuh_agent_authd_pass}"
  chmod 640 "${wazuh_agent_authd_pass}"
  logger "Wazuh agent registration password set successfully"
}

function clean_configuration(){
  logger "Cleaning configuration files"
  eval "rm -rf /var/log/wazuh-starter.log"
  eval "rm -f /etc/.wazuh-starter.sh /etc/systemd/system/wazuh-starter.service /etc/systemd/system/wazuh-starter.timer"
}


###########################################
# Main
###########################################

logger "Starting Wazuh services in order"

rotate_authd_password

starter_service wazuh-indexer
verify_indexer

starter_service wazuh-manager
set_authd_password

starter_service wazuh-agent

starter_service wazuh-dashboard
verify_dashboard
systemctl enable wazuh-manager
systemctl enable wazuh-agent
systemctl enable wazuh-dashboard

clean_configuration
