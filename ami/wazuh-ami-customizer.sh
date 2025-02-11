#!/bin/bash
# This script is used to configure the Wazuh environment after the installation

# Variables
logfile="/var/log/wazuh-ami-customizer.log"
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

function create_certificates() {
  logger "Creating certificates"
  eval "bash /etc/.wazuh-certs-tool.sh -A ${debug}"
}

###########################################
# Configuration Functions
###########################################

function configure_indexer(){
  logger "Stopping all services"
  eval "systemctl stop filebeat ${debug}"
  eval "systemctl stop wazuh-dashboard ${debug}"
  eval "systemctl stop wazuh-manager ${debug}"
  eval "systemctl stop wazuh-indexer ${debug}"
  logger "Configuring Wazuh Indexer"
  eval "rm -f /etc/wazuh-indexer/certs/* ${debug}"
  eval "cp /etc/wazuh-certificates/wazuh-indexer.pem /etc/wazuh-indexer/certs/wazuh-indexer.pem ${debug}"
  eval "cp /etc/wazuh-certificates/wazuh-indexer-key.pem /etc/wazuh-indexer/certs/wazuh-indexer-key.pem ${debug}"
  eval "cp /etc/wazuh-certificates/admin.pem /etc/wazuh-indexer/certs/admin.pem ${debug}"
  eval "cp /etc/wazuh-certificates/admin-key.pem /etc/wazuh-indexer/certs/admin-key.pem ${debug}"
  eval "cp /etc/wazuh-certificates/root-ca.pem /etc/wazuh-indexer/certs/root-ca.pem ${debug}"
  eval "chmod 500 /etc/wazuh-indexer/certs ${debug}"
  eval "chmod 400 /etc/wazuh-indexer/certs/* ${debug}"
  eval "chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs ${debug}"
  eval "systemctl start wazuh-indexer ${debug}"
  eval "/usr/share/wazuh-indexer/bin/indexer-security-init.sh ${debug}"
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

function configure_filebeat(){
  logger "Configuring Filebeat"
  eval "rm -f /etc/filebeat/certs/* ${debug}"
  eval "cp /etc/wazuh-certificates/wazuh-server.pem /etc/filebeat/certs/wazuh-server.pem ${debug}"
  eval "cp /etc/wazuh-certificates/wazuh-server-key.pem /etc/filebeat/certs/wazuh-server-key.pem ${debug}"
  eval "cp /etc/wazuh-certificates/root-ca.pem /etc/filebeat/certs/root-ca.pem ${debug}"
  eval "chmod 500 /etc/filebeat/certs ${debug}"
  eval "chmod 400 /etc/filebeat/certs/* ${debug}"
  eval "chown -R root:root /etc/filebeat/certs ${debug}"
  eval "systemctl start filebeat ${debug}"
}

function verify_filebeat() {
  logger "Waiting for Filebeat to be ready"
  if  filebeat test output | grep -q -i -w "ERROR"; then
    logger -e "Filebeat is not ready yet, trying to configure it again"
    eval "filebeat test output x ${debug}"
    configure_filebeat
  fi
}

function configure_manager(){
  logger "Configuring Wazuh Manager"
  eval "rm /var/ossec/api/configuration/security/*_key.pem ${debug}"
  eval "rm /var/ossec/api/configuration/ssl/server.* ${debug}"
  eval "systemctl start wazuh-manager ${debug}"
}

function configure_dashboard(){
  logger "Configuring Wazuh Dashboard"
  eval "rm -f /etc/wazuh-dashboard/certs/* ${debug}"
  eval "cp /etc/wazuh-certificates/wazuh-dashboard.pem /etc/wazuh-dashboard/certs/wazuh-dashboard.pem ${debug}"
  eval "cp /etc/wazuh-certificates/wazuh-dashboard-key.pem /etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem ${debug}"
  eval "cp /etc/wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/root-ca.pem ${debug}"
  eval "chmod 500 /etc/wazuh-dashboard/certs ${debug}"
  eval "chmod 400 /etc/wazuh-dashboard/certs/* ${debug}"
  eval "chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs ${debug}"
  eval "systemctl start wazuh-dashboard ${debug}"
}

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

###########################################
# Cleanup and Finalization Functions
###########################################

function clean_configuration(){
  logger "Cleaning configuration files"
  eval "rm -rf /etc/wazuh-certificates /etc/.wazuh-certs-tool.sh /etc/config.yml /etc/wazuh-certificates-tool.log /var/log/wazuh-ami-customizer.log"
  eval "rm -f /etc/.changePasswords.sh /etc/.wazuh-passwords-tool.sh /etc/.wazuh-install-files/wazuh-passwords.txt /var/log/wazuh-passwords-tool.log"
  eval "rmdir /etc/.wazuh-install-files"
  eval "rm -f /etc/.wazuh-ami-customizer.sh /etc/systemd/system/wazuh-ami-customizer.service /etc/systemd/system/wazuh-ami-customizer.timer"
}

function change_passwords(){
  logger "Changing passwords"
  new_password=$(ec2-metadata | grep "instance-id" | cut -d":" -f2 | tr -d " "| awk '{print toupper(substr($0,1,1)) substr($0,2)}')
  eval "sed -i 's/password:.*/password: ${new_password}/g' /etc/.wazuh-install-files/wazuh-passwords.txt ${debug}"
  eval "bash /etc/.wazuh-passwords-tool.sh -a -A -au wazuh -ap wazuh -f /etc/.wazuh-install-files/wazuh-passwords.txt >> /dev/null"
}

function restart_ssh_service(){
  logger "Starting SSH service"
  eval "systemctl start sshd.service"
}

###########################################
# Main
###########################################

logger "Starting Wazuh AMI Customizer"

logger "Stopping SSH service to avoid connections during the configuration"
eval "systemctl stop sshd.service"

logger "Waiting for Wazuh indexer to be ready"
until $(curl -XGET https://localhost:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null); do
  logger -w "Wazuh indexer is not ready yet, waiting 10 seconds"
  sleep 10
done

create_certificates

configure_indexer
verify_indexer

configure_filebeat
verify_filebeat

configure_manager

configure_dashboard
verify_dashboard

eval "systemctl stop wazuh-dashboard ${debug}"

change_passwords

logger "Waiting for Wazuh indexer to be ready with new password"
until $(curl -XGET https://localhost:9200/ -uadmin:${new_password} -k --max-time 120 --silent --output /dev/null); do
  sleep 10
done

eval "systemctl start wazuh-dashboard ${debug}"

restart_ssh_service

clean_configuration
