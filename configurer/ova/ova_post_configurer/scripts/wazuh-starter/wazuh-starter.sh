#!/bin/bash
# This script is used to configure the Wazuh environment after the installation
#
# Why this re-implements CertsManager's logic in bash instead of reusing it (configurer/core/models/
# certificates_manager.py, Python, already used by AMI at first boot via wazuh-ami-customizer.py):
# AMI's first boot runs inside a venv built during the AMI image build (ami_post_configurer.py:
# create_custom_dir()/create_certs_env() -- provisions python3.11 + pip install pydantic/pyyaml/
# paramiko over SSH before packaging). OVA has no equivalent build-time venv infrastructure today,
# and building one has a real cost beyond "reuse the Python": those pinned dependency versions would
# be frozen into every OVA someone downloads and runs on-prem, indefinitely, with no way to patch a
# future CVE in them short of re-publishing the whole image -- unlike AMI, which can be rebuilt and
# redeployed far more readily. The tradeoff accepted here is keeping this bash version in sync with
# CertsManager by hand; that cost is real (three bugs in this exact mirroring were only caught by
# testing a real OVA boot, not by unit tests) but preferred over baking unpatchable dependencies into
# a long-lived on-prem appliance. Revisiting this (e.g. building OVA's own venv provisioning to unify
# both onto CertsManager) is a separate initiative, not something to fold into a single issue.

# Variables
logfile="/var/log/wazuh-starter.log"
debug="| tee -a ${logfile}"

# The manager CLI that mints enrollment tokens. It is a client of the local authd socket, not a
# standalone generator, so wazuh-manager-authd has to be running before it is called.
wazuh_manager_authd_bin="/var/wazuh-manager/bin/wazuh-manager-authd"

# Where the pre-installed agent picks its enrollment token up. w_agent_token_bootstrap() reads it
# once at the agent's first start, while still root, installs the trust anchor the token carries,
# enrolls, and unlinks the file.
wazuh_agent_enrollment_token="/var/ossec/etc/enrollment_token"

# Everything the build leaves behind that would make a freshly minted token useless or unsafe. The
# bootstrap refuses to run at all when the agent already holds a trust anchor or a non-empty
# client.keys -- it deletes the token unused in both cases -- so anything baked into the image has
# to go first. See reset_enrollment_state().
wazuh_manager_authd_pass="/var/wazuh-manager/etc/authd.pass"
wazuh_manager_enrollment_tokens="/var/wazuh-manager/etc/enrollment_tokens.json"
wazuh_agent_authd_pass="/var/ossec/etc/authd.pass"
wazuh_agent_client_keys="/var/ossec/etc/client.keys"
wazuh_agent_reenroll_secret="/var/ossec/etc/reenroll.secret"

# The address the token names, and the address the pre-installed agent's <manager><endpoint> already
# holds (configurer/core/static/configuration_mappings.yaml). Manager and agent live on the same VM,
# so loopback is the one address that is always reachable and never changes. It is a SAN entry of
# remoted.pem through the manager node of the cert-tool config, and a mint only refuses an address
# the listener certificate does not name -- or a certificate whose SAN is loopback AND NOTHING ELSE,
# which is why generate_certificates() has to add this VM's own addresses first.
wazuh_agent_enrollment_address="127.0.0.1"

# The token CLI talks to queue/sockets/auth.sock, which a manager reporting "active" may still be
# opening: systemctl returns as soon as the unit is active, not once every daemon inside it has
# finished initializing. Retry instead of failing the whole first boot on that race.
enrollment_token_max_retries=12
enrollment_token_wait_time=5

# The indexer's own admin account, used to poll both the indexer and the dashboard (which
# authenticates against the indexer's security plugin). The indexer package ships admin,
# kibanaserver, wazuh-manager and wazuh-readonly. See verify_indexer().
wazuh_indexer_admin_user="admin"
wazuh_indexer_admin_password="admin"

# Both readiness waits are bounded and fatal: an indexer or dashboard that never answers is a
# broken first boot, and saying so beats looping in the background for ever.
indexer_max_retries=30
indexer_wait_time=5
dashboard_max_retries=20
dashboard_wait_time=15

# The manager's API account, for the readiness check below.
wazuh_manager_api_user="wazuh-wui"
wazuh_manager_api_password="wazuh-wui"
manager_max_retries=30
manager_wait_time=5

# The manager's agent-listener certificate (HTTPS identity, reused by Authd as the /enroll mTLS
# credential). Issued by copy_manager_certs from this instance's own CA (see generate_certificates),
# making it unique per deployed instance instead of the baked-in self-signed pair the image ships.
wazuh_manager_certs_dir="/var/wazuh-manager/etc/certs"
wazuh_manager_remoted_cert="${wazuh_manager_certs_dir}/remoted.pem"
wazuh_manager_remoted_key="${wazuh_manager_certs_dir}/remoted-key.pem"

# Persisted at build time by add_wazuh_starter_certs_tool() (ova_post_configurer.py), since the
# build-time copy under RemoteDirectories.CERTS is gone by the time this script runs. Both files
# must stay side by side under this exact directory: wazuh-certs-tool.sh resolves its own config as
# "$(dirname "$0")/config.yml", with no flag to point it elsewhere (confirmed against the real tool
# on a booted OVA -- it failed with "No configuration file found" when the config lived under a
# different name/directory), and writes its output to "$(dirname "$0")/wazuh-certificates".
wazuh_certs_dir="/etc/.wazuh-starter-certs"
wazuh_certs_tool="${wazuh_certs_dir}/certs-tool.sh"
wazuh_certs_output_dir="${wazuh_certs_dir}/wazuh-certificates"
wazuh_certs_tar="/etc/wazuh-certificates.tar"

# Where this instance's own root CA (key included) lives on, past first boot, so a leaf can be
# reissued later (e.g. the instance's address changes, or a load balancer joins) without having to
# start over with a brand new CA every enrolled agent would have to re-trust. See
# clean_configuration() for why this is kept, not deleted -- issue #957 only requires that
# root-ca.key never ships baked into the image, not that a booted instance destroy its own copy.
wazuh_ca_dir="/etc/wazuh-certificate-authority"

wazuh_indexer_certs_dir="/etc/wazuh-indexer/certs"
wazuh_dashboard_certs_dir="/etc/wazuh-dashboard/certs"
wazuh_manager_conf="/var/wazuh-manager/etc/wazuh-manager.conf"
wazuh_indexer_conf="/etc/wazuh-indexer/opensearch.yml"
wazuh_dashboard_conf="/etc/wazuh-dashboard/opensearch_dashboards.yml"

# Where the enrollment-token bootstrap installs the agent's trust anchor on its first start. This
# script no longer writes it -- it only makes sure the image did not ship one, which would make the
# bootstrap skip the token entirely.
wazuh_agent_ca="/var/ossec/etc/certs/root-ca.pem"

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
  # The indexer's admin user is `admin`. The users the indexer package ships and
  # security-init loads are admin, kibanaserver, wazuh-manager and wazuh-readonly.
  logger "Waiting for Wazuh indexer to be ready"
  local http_status retries=0 indexer_check_comm
  indexer_check_comm="curl -XGET https://localhost:9200/ -u${wazuh_indexer_admin_user}:${wazuh_indexer_admin_password} -k --max-time 120 --silent -w \"%{http_code}\" --output /dev/null"
  http_status=$(eval "${indexer_check_comm}")
  while [ "${http_status}" != "200" ]; do
      if [ "${retries}" -ge "${indexer_max_retries}" ]; then
          logger -e "Wazuh indexer is still not ready after ${retries} attempts (last HTTP status: ${http_status})"
          exit 1
      fi
      logger -w "Wazuh indexer is not ready yet, waiting ${indexer_wait_time} seconds"
      sleep "${indexer_wait_time}"
      retries=$((retries+1))
      http_status=$(eval "${indexer_check_comm}")
  done
}

function verify_manager() {
  # The manager's API (apid, port 55000) is what the dashboard talks to for everything outside the
  # indexer. Wait for the API here so that failure stops the boot where it happens.
  logger "Waiting for Wazuh manager API to be ready"
  local http_code retries=0 manager_check_comm
  manager_check_comm="curl -XPOST https://localhost:55000/security/user/authenticate -u${wazuh_manager_api_user}:${wazuh_manager_api_password} -k --max-time 120 -s -o /dev/null -w \"%{http_code}\""
  http_code=$(eval "${manager_check_comm}")
  while [ "${http_code}" != "200" ]; do
      if [ "${retries}" -ge "${manager_max_retries}" ]; then
          logger -e "Wazuh manager API is still not ready after ${retries} attempts (last HTTP status: ${http_code})"
          exit 1
      fi
      logger -w "Wazuh manager API is not ready yet, waiting ${manager_wait_time} seconds"
      sleep "${manager_wait_time}"
      retries=$((retries+1))
      http_code=$(eval "${manager_check_comm}")
  done
}

function verify_dashboard() {
  logger "Waiting for Wazuh dashboard to be ready"
  local http_code retries=0 dashboard_check_comm
  dashboard_check_comm="curl -XGET https://localhost:443/status -u${wazuh_indexer_admin_user}:${wazuh_indexer_admin_password} -k -w \"%{http_code}\" -s -o /dev/null"
  http_code=$(eval "${dashboard_check_comm}")
  while [ "${http_code}" != "200" ]; do
      if [ "${retries}" -ge "${dashboard_max_retries}" ]; then
          logger -e "Wazuh dashboard is still not ready after ${retries} attempts (last HTTP status: ${http_code})"
          exit 1
      fi
      logger -w "Wazuh dashboard is not ready yet, waiting ${dashboard_wait_time} seconds"
      sleep "${dashboard_wait_time}"
      retries=$((retries+1))
      http_code=$(eval "${dashboard_check_comm}")
  done
}

function reset_enrollment_state() {
  # Remove every enrollment credential and agent identity this image was built with. Two kinds of
  # leftovers, both of which have to go before a token minted on this VM can be used:
  #
  #   * Credentials the manager generated during the build -- its Authd password and, if anything
  #     ever minted one there, its enrollment token store. Shipped as they are, every VM imported
  #     from this OVA would share them. This is what the old rotate_authd_password() did, widened to
  #     the artifact that replaced the password.
  #   * Anything on the agent side that makes the token bootstrap decline to run. It refuses
  #     whenever the agent already holds a trust anchor or a non-empty client.keys -- on both counts
  #     it deletes the token unused and returns -- so a baked anchor or a baked key would silently
  #     turn the fresh token into a no-op and leave every imported VM enrolled under one identity.
  #
  # client.keys is truncated rather than deleted so the file keeps the ownership and mode the agent
  # package gave it; the bootstrap only looks at its size.
  logger "Removing the enrollment credentials and agent identity baked into the image"
  rm -f "${wazuh_manager_authd_pass}" "${wazuh_manager_enrollment_tokens}"
  rm -f "${wazuh_agent_authd_pass}" "${wazuh_agent_enrollment_token}"
  rm -f "${wazuh_agent_ca}" "${wazuh_agent_reenroll_secret}"
  if [ -f "${wazuh_agent_client_keys}" ]; then
      : > "${wazuh_agent_client_keys}"
  fi
}

function set_agent_enrollment_token() {
  # Mint a fresh enrollment token on this VM and leave it where the pre-installed agent reads it.
  #
  # Replaces the old authd.pass copy: the manager no longer hands the agent a shared registration
  # password, it mints a credential for that one agent (wazuh/wazuh#39063). The agent reads this
  # file on its first start, while it is still root, installs the CA the token carries as its trust
  # anchor, enrolls, and unlinks the file -- which is also why set_agent_ssl_ca() is gone: copying
  # the CA by hand beforehand would make the bootstrap skip the token and never enroll.
  #
  # The token is minted, never baked: it is created here, against the CA and the listener
  # certificate this VM generated for itself moments earlier in generate_certificates(). Its 30-day
  # TTL (the CLI default, wazuh/wazuh#39068) is therefore irrelevant and is left alone on purpose --
  # a token is minted on every first boot and consumed within seconds, so it never gets anywhere
  # near expiring. Do NOT "fix" this later by minting a long-lived token at build time and shipping
  # it in the image: that hands every VM imported from this OVA the same credential, which is the
  # whole reason this runs here.
  #
  # --embed-ca carries the CA inside the token instead of a pin of it, so the agent has its trust
  # anchor without first fetching /cacerts over a connection it cannot verify yet. --max-uses 1
  # because exactly one agent, the one on this VM, will ever use it.
  #
  # The CLI prints the token alone on stdout and everything else (id, endpoint, expiry) on stderr,
  # so stderr is left going to the log while stdout is captured. The token is written with a
  # redirection and never appears as a command argument, where any local user could read it off the
  # process list. The file is created and locked down to 0600 root:root BEFORE the token goes into
  # it, the same way the agent installer writes it, so the credential is never briefly readable.
  logger "Minting the enrollment token for the pre-installed agent"
  local token retries=0
  token=""
  while [ -z "${token}" ] && [ "${retries}" -lt "${enrollment_token_max_retries}" ]; do
      token=$("${wazuh_manager_authd_bin}" --create-enrollment-token \
          --address "${wazuh_agent_enrollment_address}" \
          --embed-ca \
          --max-uses 1 \
          --description "Pre-installed agent, minted on first boot")
      if [ -z "${token}" ]; then
          logger -w "Could not mint the enrollment token yet, waiting ${enrollment_token_wait_time} seconds"
          sleep "${enrollment_token_wait_time}"
          retries=$((retries+1))
      fi
  done
  if [ -z "${token}" ]; then
      logger -e "Could not mint the enrollment token for the pre-installed agent"
      exit 1
  fi

  : > "${wazuh_agent_enrollment_token}"
  chmod 600 "${wazuh_agent_enrollment_token}"
  chown root:root "${wazuh_agent_enrollment_token}"
  printf '%s' "${token}" > "${wazuh_agent_enrollment_token}"
  logger "Enrollment token stored successfully"
}

function get_manager_san_ips() {
  # Every address agents might dial to reach this instance's manager, for remoted.pem's SAN.
  #
  # DEPENDS ON wazuh-installation-assistant#1027 (Victor Ereñú, opened 2026-09-16, NOT MERGED as of
  # this writing) -- speculative against that issue's description, written ahead of the merge so
  # there's less to wire up once it lands. Verify against the real tool before trusting this: same
  # convention as everywhere else in this file (read the generator, don't assume).
  #
  # Deliberately does NOT edit config.yml's manager node (unlike the previous approach here, which
  # overwrote its scalar `ip: "127.0.0.1"` with the single detected address -- a real regression,
  # caught but never confirmed live: the pre-installed agent dials 127.0.0.1 literally, hardcoded in
  # configurer/core/static/configuration_mappings.yaml's agent.manager.endpoint, so dropping that
  # value from the SAN could break its own TLS verification). #1027 adds `-as/--agent-san <ip|dns>`
  # to wazuh-certs-tool.sh, repeatable, additive on top of each node's existing ip/dns -- so
  # config.yml keeps whatever build time already baked in (127.0.0.1, matching indexer/dashboard and
  # the pre-installed agent) untouched, and every address here just gets appended via that flag in
  # generate_certificates() instead of replacing anything.
  #
  # OVA is not EC2 (see the file header for why this differs from AMI's equivalent, which also
  # queries ec2-metadata for a public IP): hostname -I is the only source available here.
  #
  # Confirmed on a real OVA boot (2026-09-17): wazuh-starter.timer's OnBootSec=10s has no ordering
  # against networking coming up, and at 10s post-boot hostname -I can still be empty -- the
  # resulting cert generation silently got zero --agent-san flags (no error, no warning), passing
  # everyone's review because it worked fine on the same instance minutes later. Retry instead of
  # trusting the first read; same bounded wait_time/retries pattern used elsewhere in this file
  # (set_agent_enrollment_token).
  #
  # logger's own output must stay off stdout here (redirected to &2 below): the caller reads this
  # function's stdout as its return value (`for ip in $(get_manager_san_ips)`), and logger's
  # printf|tee also writes to stdout -- unredirected, a retry warning would get fed to
  # wazuh-certs-tool.sh as a bogus --agent-san value instead of just being logged. Caught locally
  # (isolated stub test) before this ever reached a real boot.
  local ips retries=0 max_retries=5 wait_time=2
  ips=$(hostname -I)
  while [[ -z "${ips// /}" ]] && [[ "${retries}" -lt "${max_retries}" ]]; do
    logger -w "No network address available yet for the manager cert SAN, waiting ${wait_time} seconds" >&2
    sleep "${wait_time}"
    retries=$((retries + 1))
    ips=$(hostname -I)
  done
  if [[ -z "${ips// /}" ]]; then
    logger -w "No network address found after ${max_retries} retries; remoted.pem's SAN will only cover 127.0.0.1" >&2
  fi
  echo "${ips}"
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

  local -a agent_san_flags=()
  local ip
  for ip in $(get_manager_san_ips); do
    agent_san_flags+=(--agent-san "${ip}")
  done

  run_or_die "wazuh-certs-tool.sh failed to generate certificates" \
      sudo bash "${wazuh_certs_tool}" -A "${agent_san_flags[@]}"
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

function clean_configuration(){
  logger "Cleaning configuration files"
  eval "rm -rf /var/log/wazuh-starter.log"
  eval "rm -f /etc/.wazuh-starter.sh /etc/systemd/system/wazuh-starter.service /etc/systemd/system/wazuh-starter.timer"
  # wazuh_certs_tar carries the CA private key (the tar packs the cert-tool's whole output
  # unfiltered) with none of the 500/400 restrictive permissions copy_*_certs applies to what it
  # extracts into each component's own directory -- left as the tool wrote it, that's exactly the
  # persisted, loosely-permissioned key material issue #957 set out to remove.
  #
  # The fix is to secure root-ca.pem/root-ca.key in a fixed, restrictive location, NOT to destroy
  # them: the issue only requires that root-ca.key never ship baked into the image (a single CA
  # shared by every copy of it), not that a booted instance erase its own copy. Its own acceptance
  # criteria assume the opposite -- "reissuing the leaf is enough and does not break enrolled
  # agents, since they pin the CA rather than the leaf" only holds if that CA still exists to sign a
  # new leaf with, e.g. after the instance's address changes or a load balancer joins later. An
  # earlier revision of this function deleted them outright instead, which satisfied the letter of
  # "not baked into the image" but broke that reissuing guarantee for every OVA -- caught only by
  # tracing the issue's exact wording, not by anything that runs. wazuh-installation-assistant, which
  # this whole first-boot design otherwise mirrors, never destroys its equivalent either: it
  # chmod 400s the generated root-ca.pem/key and bundles them into wazuh-install-files.tar for the
  # operator to keep (install_functions/installCommon.sh).
  run_or_die "Failed to extract the CA into ${wazuh_ca_dir}" \
      sudo mkdir -p "${wazuh_ca_dir}"
  run_or_die "Failed to extract the CA into ${wazuh_ca_dir}" \
      sudo tar -xf "${wazuh_certs_tar}" -C "${wazuh_ca_dir}" ./root-ca.pem ./root-ca.key
  sudo chown -R root:root "${wazuh_ca_dir}"
  sudo chmod 700 "${wazuh_ca_dir}"
  sudo chmod 400 "${wazuh_ca_dir}/root-ca.pem" "${wazuh_ca_dir}/root-ca.key"

  eval "rm -f ${wazuh_certs_tar}"
  eval "rm -rf ${wazuh_certs_dir}"
}


###########################################
# Main
###########################################

logger "Starting Wazuh services in order"

reset_enrollment_state
generate_certificates
copy_indexer_certs
copy_manager_certs
copy_dashboard_certs

starter_service wazuh-indexer
verify_indexer

starter_service wazuh-manager
verify_manager
# Minting goes through the manager's local authd socket, so it has to happen after the manager is
# up; the bootstrap only looks for the token file at the agent's first start, so it has to happen
# before the agent starts.
set_agent_enrollment_token

starter_service wazuh-agent

starter_service wazuh-dashboard
verify_dashboard
systemctl enable wazuh-manager
systemctl enable wazuh-agent
systemctl enable wazuh-dashboard

clean_configuration
