#!/bin/bash
# This script is used to configure the Wazuh environment after the installation

# Variables
logfile="/var/log/wazuh-starter.log"
debug="| tee -a ${logfile}"

# The Wazuh manager generates a random Authd registration password on startup and persists it in
# this file. The same password must be distributed to the agent so it can enroll against the manager.
wazuh_manager_authd_pass="/var/wazuh-manager/etc/authd.pass"
wazuh_agent_authd_pass="/var/ossec/etc/authd.pass"

# The manager's agent-listener certificate (HTTPS identity, reused by Authd as the /enroll mTLS
# credential). Issued by copy_manager_certs from this instance's own CA (see generate_certificates),
# making it unique per deployed instance instead of the baked-in self-signed pair the image ships.
wazuh_manager_certs_dir="/var/wazuh-manager/etc/certs"
wazuh_manager_remoted_cert="${wazuh_manager_certs_dir}/remoted.pem"
wazuh_manager_remoted_key="${wazuh_manager_certs_dir}/remoted-key.pem"
authd_pass_max_retries=12
authd_pass_wait_time=5

# Persisted at build time by add_wazuh_starter_certs_tool() (ova_post_configurer.py), since the
# build-time copy under RemoteDirectories.CERTS is gone by the time this script runs. Both files
# must stay side by side under this exact directory: wazuh-certs-tool.sh resolves its own config as
# "$(dirname "$0")/config.yml", with no flag to point it elsewhere (confirmed against the real tool
# on a booted OVA -- it failed with "No configuration file found" when the config lived under a
# different name/directory), and writes its output to "$(dirname "$0")/wazuh-certificates".
wazuh_certs_dir="/etc/.wazuh-starter-certs"
wazuh_certs_tool="${wazuh_certs_dir}/certs-tool.sh"
wazuh_certs_config="${wazuh_certs_dir}/config.yml"
wazuh_certs_output_dir="${wazuh_certs_dir}/wazuh-certificates"
wazuh_certs_tar="/etc/wazuh-certificates.tar"

wazuh_indexer_certs_dir="/etc/wazuh-indexer/certs"
wazuh_dashboard_certs_dir="/etc/wazuh-dashboard/certs"
wazuh_manager_conf="/var/wazuh-manager/etc/wazuh-manager.conf"
wazuh_indexer_conf="/etc/wazuh-indexer/opensearch.yml"
wazuh_dashboard_conf="/etc/wazuh-dashboard/opensearch_dashboards.yml"

# Path the agent's <certificate_authorities> config points at, so it trusts this instance's own
# manager now that verification_mode is enforced by default.
wazuh_agent_ca_dir="/var/ossec/etc/certs"
wazuh_agent_ca="${wazuh_agent_ca_dir}/root-ca.pem"

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

function get_manager_san_ip() {
  # The address agents may dial to reach this instance's manager, for the manager cert's (and
  # remoted's) SAN. wazuh-certs-tool.sh's manager node takes a single scalar `ip:` value, not a
  # list -- confirmed empirically on a real OVA boot: unlike `dns` (whose regex allows an indexed
  # suffix, "nodes_manager_N_dns([_]+[0-9]+)?="), the `ip` lookup regex
  # ("nodes_manager_N_ip=") has no such suffix, so a YAML list under manager.ip parses to
  # "..._ip_1"/"..._ip_2" keys that never match it and the tool aborts with "requires at least one
  # field: ip or dns". So, unlike AMI's get_manager_san_ips() (wazuh-ami-customizer.py, which
  # builds a list from hostname -I + ec2-metadata for a list-style manager_san_ips -- itself
  # affected by the same tool limitation, reported separately, out of scope for #957), this returns
  # just the first address hostname -I reports, or nothing if it hasn't configured one yet.
  hostname -I | awk '{print $1}'
}

function set_certs_config_manager_san_ips() {
  # Mirrors CertsManager._set_config_file_values()'s no-manager_san_ips branch: sets node
  # names/IPs in the persisted certs-tool config as scalars, pointing the manager node at this
  # instance's own address so remoted's SAN matches something agents can actually reach. Falls back
  # to loopback-only if hostname -I hasn't configured an address yet.
  logger "Setting manager IP in the certs-tool config"
  local manager_ip
  manager_ip=$(get_manager_san_ip)
  manager_ip="${manager_ip:-127.0.0.1}"

  local yq_program
  yq_program=$(cat <<EOF
.nodes.indexer[0].name = "indexer" |
.nodes.indexer[0].ip = "127.0.0.1" | .nodes.indexer[0].ip style="double" |
.nodes.manager[0].name = "manager" |
.nodes.manager[0].ip = "${manager_ip}" | .nodes.manager[0].ip style="double" |
.nodes.dashboard[0].name = "dashboard" |
.nodes.dashboard[0].ip = "127.0.0.1" | .nodes.dashboard[0].ip style="double"
EOF
)
  sudo yq -i "${yq_program}" "${wazuh_certs_config}"
}

function run_or_die() {
  # $1: error message, rest: the command to run. "Fail loud, don't limp on" so tar/mv/cert-tool
  # failures during first boot can't leave certs half-installed without anyone noticing (a tar
  # that's missing a requested member, or a cert-tool that errors out, exits non-zero -- verified
  # locally).
  local error_message="$1"
  shift
  if ! "$@"; then
    logger -e "${error_message}"
    exit 1
  fi
}

function read_cert_name() {
  # $1: yq query, $2: config file to read it from. Mirrors
  # CertsManager._get_cert_name_from_key(): reads the certificate filename each component's config
  # actually expects instead of assuming the cert-tool's default names survive unchanged.
  local query="$1" file="$2" yq_flags="" value
  if [[ "${file}" == *.conf ]]; then
    yq_flags="-p xml -o xml"  # wazuh-manager.conf is XML, not YAML
  fi
  # shellcheck disable=SC2086 # yq_flags is a deliberate word-split: quoting it would pass "-p xml -o xml" as one flag
  value=$(sudo yq ${yq_flags} "${query}" "${file}")
  if [[ -z "${value}" ]]; then
    logger -e "yq query '${query}' on ${file} returned no certificate path"
    exit 1
  fi
  if [[ "${value}" == *"["*"]"* ]]; then
    # Some config keys (confirmed on a real boot: opensearch.ssl.certificateAuthorities) hold a
    # list of CA paths, e.g. yq prints "['/path/root-ca.pem']". Mirrors
    # CertsManager._get_cert_name_from_key()'s ast.literal_eval(output)[-1]: take the last element.
    # Without this, basename kept the raw bracket/quote text, producing a garbage filename.
    value="${value#*[}"
    value="${value%]*}"
    value="${value##*,}"
    value="${value#\'}"
    value="${value%\'}"
    value="${value#\"}"
    value="${value%\"}"
  fi
  basename "${value}"
}

function generate_certificates() {
  # Mirrors CertsManager.generate_certificates() (Python, used by AMI): run wazuh-certs-tool.sh,
  # then compress its output the same way, so the copy_*_certs() functions below can extract from a
  # fixed tar path regardless of the tool's own working directory.
  logger "Generating the CA and all component certificates for this instance"
  set_certs_config_manager_san_ips
  run_or_die "wazuh-certs-tool.sh failed to generate certificates" sudo bash "${wazuh_certs_tool}" -A
  run_or_die "Failed to compress generated certificates into ${wazuh_certs_tar}" \
      sudo tar -cf "${wazuh_certs_tar}" -C "${wazuh_certs_output_dir}/" .
  sudo rm -rf "${wazuh_certs_output_dir}"
}

function copy_indexer_certs() {
  # Mirrors copy_certs_to_component_directory(Component.WAZUH_INDEXER) in certificates_manager.py.
  logger "Installing indexer certificates"
  local cert_name key_name ca_name
  cert_name=$(read_cert_name '.["plugins.security.ssl.http.pemcert_filepath"]' "${wazuh_indexer_conf}")
  key_name=$(read_cert_name '.["plugins.security.ssl.http.pemkey_filepath"]' "${wazuh_indexer_conf}")
  ca_name=$(read_cert_name '.["plugins.security.ssl.http.pemtrustedcas_filepath"]' "${wazuh_indexer_conf}")

  sudo rm -rf "${wazuh_indexer_certs_dir}"
  sudo mkdir -p "${wazuh_indexer_certs_dir}"
  run_or_die "Failed to extract indexer certificates from ${wazuh_certs_tar}" \
      sudo tar -xf "${wazuh_certs_tar}" -C "${wazuh_indexer_certs_dir}" \
      ./indexer.pem ./indexer-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
  sudo mv -n "${wazuh_indexer_certs_dir}/indexer.pem" "${wazuh_indexer_certs_dir}/${cert_name}"
  sudo mv -n "${wazuh_indexer_certs_dir}/indexer-key.pem" "${wazuh_indexer_certs_dir}/${key_name}"
  sudo mv -n "${wazuh_indexer_certs_dir}/root-ca.pem" "${wazuh_indexer_certs_dir}/${ca_name}"
  sudo chmod 500 "${wazuh_indexer_certs_dir}"
  sudo find "${wazuh_indexer_certs_dir}" -type f -exec chmod 400 {} \;
  sudo chown -R wazuh-indexer:wazuh-indexer "${wazuh_indexer_certs_dir}/"
}

function copy_manager_certs() {
  # Mirrors copy_certs_to_component_directory(Component.WAZUH_MANAGER) in certificates_manager.py.
  # No rm -rf: the manager package's postinstall still populates this directory with authd/apid
  # daemon certs, which must survive untouched. remoted.pem/-key.pem are the exception -- force
  # replaced (mv -f, not -n) since a manager package that still self-signs its own listener
  # certificate at install time leaves a pair here too.
  logger "Installing manager certificates"
  local cert_name key_name ca_name
  cert_name=$(read_cert_name '.wazuh_config.indexer.ssl.certificate' "${wazuh_manager_conf}")
  key_name=$(read_cert_name '.wazuh_config.indexer.ssl.key' "${wazuh_manager_conf}")
  ca_name=$(read_cert_name '.wazuh_config.indexer.ssl.certificate_authorities.ca' "${wazuh_manager_conf}")

  sudo mkdir -p "${wazuh_manager_certs_dir}"
  run_or_die "Failed to extract manager certificates from ${wazuh_certs_tar}" \
      sudo tar -xf "${wazuh_certs_tar}" -C "${wazuh_manager_certs_dir}" \
      ./manager.pem ./manager-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem \
      ./manager-remoted.pem ./manager-remoted-key.pem
  sudo mv -n "${wazuh_manager_certs_dir}/manager.pem" "${wazuh_manager_certs_dir}/${cert_name}"
  sudo mv -n "${wazuh_manager_certs_dir}/manager-key.pem" "${wazuh_manager_certs_dir}/${key_name}"
  sudo mv -n "${wazuh_manager_certs_dir}/root-ca.pem" "${wazuh_manager_certs_dir}/${ca_name}"
  sudo mv -f "${wazuh_manager_certs_dir}/manager-remoted.pem" "${wazuh_manager_remoted_cert}"
  sudo mv -f "${wazuh_manager_certs_dir}/manager-remoted-key.pem" "${wazuh_manager_remoted_key}"
  sudo chown root:wazuh-manager "${wazuh_manager_certs_dir}/${cert_name}" "${wazuh_manager_certs_dir}/${key_name}" "${wazuh_manager_certs_dir}/${ca_name}"
  sudo chmod 640 "${wazuh_manager_certs_dir}/${cert_name}" "${wazuh_manager_certs_dir}/${key_name}" "${wazuh_manager_certs_dir}/${ca_name}"
  sudo chown wazuh-manager:wazuh-manager "${wazuh_manager_remoted_cert}" "${wazuh_manager_remoted_key}"
  sudo chmod 640 "${wazuh_manager_remoted_cert}" "${wazuh_manager_remoted_key}"
  sudo chown root:wazuh-manager "${wazuh_manager_certs_dir}"
  sudo chmod 1770 "${wazuh_manager_certs_dir}"
}

function copy_dashboard_certs() {
  # Mirrors copy_certs_to_component_directory(Component.WAZUH_DASHBOARD) in certificates_manager.py.
  logger "Installing dashboard certificates"
  local cert_name key_name ca_name
  cert_name=$(read_cert_name '.["server.ssl.certificate"]' "${wazuh_dashboard_conf}")
  key_name=$(read_cert_name '.["server.ssl.key"]' "${wazuh_dashboard_conf}")
  ca_name=$(read_cert_name '.["opensearch.ssl.certificateAuthorities"]' "${wazuh_dashboard_conf}")

  sudo rm -rf "${wazuh_dashboard_certs_dir}"
  sudo mkdir -p "${wazuh_dashboard_certs_dir}"
  run_or_die "Failed to extract dashboard certificates from ${wazuh_certs_tar}" \
      sudo tar -xf "${wazuh_certs_tar}" -C "${wazuh_dashboard_certs_dir}" \
      ./dashboard.pem ./dashboard-key.pem ./root-ca.pem
  sudo mv -n "${wazuh_dashboard_certs_dir}/dashboard.pem" "${wazuh_dashboard_certs_dir}/${cert_name}"
  sudo mv -n "${wazuh_dashboard_certs_dir}/dashboard-key.pem" "${wazuh_dashboard_certs_dir}/${key_name}"
  sudo mv -n "${wazuh_dashboard_certs_dir}/root-ca.pem" "${wazuh_dashboard_certs_dir}/${ca_name}"
  sudo chmod 500 "${wazuh_dashboard_certs_dir}"
  sudo find "${wazuh_dashboard_certs_dir}" -type f -exec chmod 400 {} \;
  sudo chown -R wazuh-dashboard:wazuh-dashboard "${wazuh_dashboard_certs_dir}/"
}

function set_agent_ssl_ca() {
  # Copy the manager's root CA to the path the agent's <certificate_authorities> config points at,
  # so it can verify this instance's own manager now that remoted/manager certs are issued from
  # that CA by copy_manager_certs, instead of a self-signed remoted pair -- pinning the CA is
  # enough, no separate per-instance remoted trust anchor needed. Must run after copy_manager_certs.
  # Re-reads the CA's on-disk name from the manager config rather than assuming it is still called
  # root-ca.pem, since copy_manager_certs may have renamed it (mv -n root-ca.pem -> ${ca_name}).
  logger "Setting the Wazuh agent trusted CA from the manager root CA"
  local ca_name
  ca_name=$(read_cert_name '.wazuh_config.indexer.ssl.certificate_authorities.ca' "${wazuh_manager_conf}")
  mkdir -p "${wazuh_agent_ca_dir}"
  cp "${wazuh_manager_certs_dir}/${ca_name}" "${wazuh_agent_ca}"
  chown root:wazuh "${wazuh_agent_ca}"
  chmod 640 "${wazuh_agent_ca}"
  logger "Wazuh agent trusted CA set successfully"
}

function clean_configuration(){
  logger "Cleaning configuration files"
  eval "rm -rf /var/log/wazuh-starter.log"
  eval "rm -f /etc/.wazuh-starter.sh /etc/systemd/system/wazuh-starter.service /etc/systemd/system/wazuh-starter.timer"
  # wazuh_certs_tar and wazuh_certs_dir (which by now also holds the tool's own output dir, see
  # generate_certificates) both carry the CA private key (the tar packs the cert-tool's whole output
  # unfiltered; the tool writes its generated keys next to its own config.yml) -- neither is
  # extracted into a component directory by copy_*_certs, so unlike those, nothing else applies the
  # 500/400 restrictive permissions to them. Left behind, they're the exact kind of persisted,
  # loosely-permissioned key material issue #957 set out to remove. AMI's equivalent
  # (wazuh-ami-customizer.py) wipes the same artifacts via its temp dir cleanup.
  eval "rm -f ${wazuh_certs_tar}"
  eval "rm -rf ${wazuh_certs_dir}"
}


###########################################
# Main
###########################################

logger "Starting Wazuh services in order"

rotate_authd_password
generate_certificates
copy_indexer_certs
copy_manager_certs
copy_dashboard_certs

starter_service wazuh-indexer
verify_indexer

starter_service wazuh-manager
set_authd_password
set_agent_ssl_ca

starter_service wazuh-agent

starter_service wazuh-dashboard
verify_dashboard
systemctl enable wazuh-manager
systemctl enable wazuh-agent
systemctl enable wazuh-dashboard

clean_configuration
