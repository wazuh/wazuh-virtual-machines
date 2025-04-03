#!/bin/bash
# This script is used to configure the Wazuh environment after the installation

# Variables
logfile="/var/log/wazuh-starter.log"
debug="| tee -a ${logfile}"

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
  indexer_security_admin_comm="curl -XGET https://localhost:9200/ -uadmin:admin -k --max-time 120 --silent -w \"%{http_code}\" --output /dev/null"
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

# function verify_filebeat() {
#   logger "Waiting for Filebeat to be ready"
#   if  filebeat test output | grep -q -i -w "ERROR"; then
#     logger -e "Filebeat is not ready yet, trying to configure it again"
#     eval "filebeat test output x ${debug}"
#     configure_filebeat
#   fi
# }

function verify_dashboard() {
  logger "Waiting for Wazuh dashboard to be ready"
  dashboard_check_comm="curl -XGET https://localhost:443/status -uadmin:admin -k -w \"%{http_code}\" -s -o /dev/null"
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

function clean_configuration(){
  logger "Cleaning configuration files"
  eval "rm -rf /var/log/wazuh-starter.log"
  eval "rm -f /etc/.wazuh-starter.sh /etc/systemd/system/wazuh-starter.service /etc/systemd/system/wazuh-starter.timer"
}


###########################################
# Main
###########################################

logger "Starting Wazuh services in order"


starter_service wazuh-indexer
verify_indexer

starter_service wazuh-manager
starter_service filebeat
verify_filebeat

starter_service wazuh-dashboard
verify_dashboard
systemctl enable wazuh-manager
systemctl enable wazuh-dashboard

clean_configuration