#!/bin/bash
# This script is used to configure the Wazuh environment after the installation
#
# First boot of the OVA: each package issues this VM's certificates (`resolve-credentials --install`),
# then every service starts in order and the pre-installed agent enrolls with a freshly minted token.
# The AMI's equivalent is configurer/ami/ami_post_configurer/wazuh-ami-customizer.py.

# Variables
logfile="/var/log/wazuh-starter.log"
debug="| tee -a ${logfile}"

# The manager's configuration directory since wazuh/wazuh#40346 (/var/wazuh-manager/etc is gone, no
# symlink). Keep it in sync with WAZUH_MANAGER_CONF_DIR in configurer/core/utils/enums.py.
wazuh_manager_conf_dir="/etc/wazuh-manager"

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
# to go first. See reset_enrollment_state() and reset_agent_identity().
wazuh_manager_authd_pass="${wazuh_manager_conf_dir}/authd.pass"
wazuh_manager_enrollment_tokens="${wazuh_manager_conf_dir}/enrollment_tokens.json"
wazuh_agent_authd_pass="/var/ossec/etc/authd.pass"
wazuh_agent_client_keys="/var/ossec/etc/client.keys"
wazuh_agent_reenroll_secret="/var/ossec/etc/reenroll.secret"

# The address the token names, and the address the pre-installed agent's <manager><endpoint> already
# holds (configurer/core/static/configuration_mappings.yaml). Manager and agent live on the same VM,
# so loopback is the one address that is always reachable and never changes. The manager's resolver
# always adds it to remoted.pem's SANs, and a mint only refuses an address the listener certificate
# does not name -- or a certificate whose SAN is loopback AND NOTHING ELSE, which is why
# install_credentials() waits for this VM's own address first (wait_for_network_address).
wazuh_agent_enrollment_address="127.0.0.1"

# The token CLI talks to queue/sockets/auth.sock, which a manager reporting "active" may still be
# opening: systemctl returns as soon as the unit is active, not once every daemon inside it has
# finished initializing. Retry instead of failing the whole first boot on that race.
enrollment_token_max_retries=12
enrollment_token_wait_time=5

# The passwords are not known in advance: each package generates its own when its service first
# starts (`resolve-credentials --prestart`) and publishes them to its own export/credentials.env
# (RC 2): the indexer its users' passwords, the manager the Server API ones. Both stay on the VM as
# the record the user reads them from. They are parsed, never sourced, and a value read from them
# only ever reaches curl through its standard input. Same split as credentials_file_for() in
# configurer/core/utils/credentials.py.
wazuh_indexer_credentials_file="/etc/wazuh-indexer/export/credentials.env"
wazuh_manager_credentials_file="${wazuh_manager_conf_dir}/export/credentials.env"

# The indexer's own admin account, used to poll both the indexer and the dashboard (which
# authenticates against the indexer's security plugin). See verify_indexer().
wazuh_indexer_admin_user="admin"
wazuh_indexer_admin_key="WAZUH_INDEXER_ADMIN_PASSWORD"

# Both readiness waits are bounded and fatal: an indexer or dashboard that never answers is a
# broken first boot, and saying so beats looping in the background for ever.
indexer_max_retries=30
indexer_wait_time=5
dashboard_max_retries=20
dashboard_wait_time=15

# The manager's API account the dashboard uses, for the readiness check below.
wazuh_manager_api_user="wazuh-internal-client"
wazuh_manager_api_key="WAZUH_MANAGER_WUI_PASSWORD"
manager_max_retries=30
manager_wait_time=5

# Publishes the manager's certs/root-ca.pem to the agents (wazuh/wazuh#39319); see install_credentials().
wazuh_manager_certs_bin="/var/wazuh-manager/bin/wazuh-manager-certs"

# Each package's credential resolver. `--install` mints the package's CA and issues its pairs; it is
# the only mode that issues certificates, so first boot runs it again after the build purge cleared
# what the packages' postinst made (wazuh/internal-devel-requests#7048). In this order: the manager
# and the dashboard import the indexer's export/, the dashboard also the manager's. No local.env is
# written: on the OVA every address agents dial is on a default-route interface, which is what each
# resolver puts in its certificates' SANs when it is given no list.
credential_resolvers=(
  /usr/share/wazuh-indexer/bin/resolve-credentials.sh
  /var/wazuh-manager/bin/wazuh-manager-resolve-credentials
  /usr/share/wazuh-dashboard/bin/resolve-credentials
)

# Where the enrollment-token bootstrap installs the agent's trust anchor on its first start. This
# script no longer writes it -- it only makes sure the image did not ship one, which would make the
# bootstrap skip the token entirely.
wazuh_agent_ca="/var/ossec/etc/certs/root-ca.pem"
# The marker the agent writes once it has committed to a trust anchor. With the marker present and
# the anchor gone, agentd refuses to start (error 4125) instead of bootstrapping a new one, so it has
# to go together with the anchor. Only there when an earlier, failed run of this script enrolled the
# agent before dying.
wazuh_agent_anchor_committed="/var/ossec/etc/certs/.anchor-committed"

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
  if ! systemctl start "$1"; then
    # Each package's `resolve-credentials --prestart` (ExecStartPre) refuses the start with a
    # MISSING, INVALID or UNSAFE line; without them, log the last lines of the unit.
    logger -e "$1 did not start:"
    journalctl -u "$1" -n 50 --no-pager -o cat | grep -E 'MISSING|INVALID|UNSAFE' \
      || journalctl -u "$1" -n 50 --no-pager -o cat
    exit 1
  fi
}

function get_credential() {
  # $1: key. Prints its value from the credentials file of the package that owns it, parsed the way
  # the packages' shared library reads it (last assignment wins, surrounding quotes removed). Never
  # sourced: sourcing would run the file as shell.
  local file="${wazuh_indexer_credentials_file}"
  case "$1" in WAZUH_MANAGER_*) file="${wazuh_manager_credentials_file}" ;; esac
  sed -n "s/^${1}=//p" "${file}" 2>/dev/null | tail -n 1 \
    | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}

function http_status() {
  # $1: URL, $2: user, $3: credentials key holding that user's password, $4: method (default GET).
  # Prints the HTTP status code. The password goes to curl through its standard input (`-K -`),
  # never argv, where any local user could read it off the process list, and is never logged.
  local url="$1" user="$2" key="$3" method="${4:-GET}" password
  password=$(get_credential "${key}")
  printf 'user = "%s:%s"\n' "${user}" "${password}" \
    | curl -s -k -K - -X "${method}" --max-time 120 -o /dev/null -w "%{http_code}" "${url}"
}

function wait_for_indexer() {
  # The indexer answers 503 until its security configuration is loaded, so this only waits for it to
  # listen; verify_indexer() checks authentication once indexer-security-init.sh has run.
  logger "Waiting for Wazuh indexer to listen on 9200"
  local code retries=0
  code=$(curl -s -k --max-time 10 -o /dev/null -w "%{http_code}" https://localhost:9200/)
  while [ "${code}" = "000" ]; do
      if [ "${retries}" -ge "${indexer_max_retries}" ]; then
          logger -e "Wazuh indexer is still not listening after ${retries} attempts"
          exit 1
      fi
      sleep "${indexer_wait_time}"
      retries=$((retries+1))
      code=$(curl -s -k --max-time 10 -o /dev/null -w "%{http_code}" https://localhost:9200/)
  done
}

function run_indexer_security_init() {
  # Loading the security configuration stays a manual step of the indexer package: it uploads the
  # digests the indexer's --prestart just wrote into internal_users.yml.
  logger "Loading the Wazuh indexer security configuration"
  run_or_die "indexer-security-init.sh failed" \
      bash /usr/share/wazuh-indexer/bin/indexer-security-init.sh -ho 127.0.0.1
}

function verify_indexer() {
  # As admin, with the password the indexer package generated on this boot.
  logger "Waiting for Wazuh indexer to be ready"
  local http_status retries=0
  http_status=$(http_status https://localhost:9200/ "${wazuh_indexer_admin_user}" "${wazuh_indexer_admin_key}")
  while [ "${http_status}" != "200" ]; do
      if [ "${retries}" -ge "${indexer_max_retries}" ]; then
          logger -e "Wazuh indexer is still not ready after ${retries} attempts (last HTTP status: ${http_status})"
          exit 1
      fi
      logger -w "Wazuh indexer is not ready yet, waiting ${indexer_wait_time} seconds"
      sleep "${indexer_wait_time}"
      retries=$((retries+1))
      http_status=$(http_status https://localhost:9200/ "${wazuh_indexer_admin_user}" "${wazuh_indexer_admin_key}")
  done
}

function verify_manager() {
  # The manager's API (apid, port 55000) is what the dashboard talks to for everything outside the
  # indexer. Wait for the API here so that failure stops the boot where it happens.
  logger "Waiting for Wazuh manager API to be ready"
  local http_code retries=0
  http_code=$(http_status https://localhost:55000/security/user/authenticate "${wazuh_manager_api_user}" "${wazuh_manager_api_key}" POST)
  while [ "${http_code}" != "200" ]; do
      if [ "${retries}" -ge "${manager_max_retries}" ]; then
          logger -e "Wazuh manager API is still not ready after ${retries} attempts (last HTTP status: ${http_code})"
          exit 1
      fi
      logger -w "Wazuh manager API is not ready yet, waiting ${manager_wait_time} seconds"
      sleep "${manager_wait_time}"
      retries=$((retries+1))
      http_code=$(http_status https://localhost:55000/security/user/authenticate "${wazuh_manager_api_user}" "${wazuh_manager_api_key}" POST)
  done
}

function verify_dashboard() {
  # As admin, the account the user logs in with. The dashboard only answers once it has authenticated
  # to the indexer as kibanaserver, so this also covers that pair.
  logger "Waiting for Wazuh dashboard to be ready"
  local http_code retries=0
  http_code=$(http_status https://localhost:443/status "${wazuh_indexer_admin_user}" "${wazuh_indexer_admin_key}")
  while [ "${http_code}" != "200" ]; do
      if [ "${retries}" -ge "${dashboard_max_retries}" ]; then
          logger -e "Wazuh dashboard is still not ready after ${retries} attempts (last HTTP status: ${http_code})"
          exit 1
      fi
      logger -w "Wazuh dashboard is not ready yet, waiting ${dashboard_wait_time} seconds"
      sleep "${dashboard_wait_time}"
      retries=$((retries+1))
      http_code=$(http_status https://localhost:443/status "${wazuh_indexer_admin_user}" "${wazuh_indexer_admin_key}")
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
  # client.keys is left alone here: reset_agent_identity() empties it once the manager API is up.
  logger "Removing the enrollment credentials and agent identity baked into the image"
  rm -f "${wazuh_manager_authd_pass}" "${wazuh_manager_enrollment_tokens}"
  rm -f "${wazuh_agent_authd_pass}" "${wazuh_agent_enrollment_token}"
  rm -f "${wazuh_agent_ca}" "${wazuh_agent_anchor_committed}" "${wazuh_agent_reenroll_secret}"
}

function reset_agent_identity() {
  # Empty the agent's client.keys, first removing from the manager the agent it names, if any.
  #
  # The image ships client.keys empty, so an ID in it can only come from an earlier run of this
  # script that enrolled the agent and then failed (this script only deletes itself once it
  # succeeds). The manager still has that agent registered under the same name and would reject the
  # new enrollment as a duplicate. On a normal first boot this only truncates an empty file.
  #
  # Reading the ID, removing the agent and truncating the file happen in this one step, after the
  # manager API is up, so a run that fails earlier (certificates, indexer, manager) leaves the ID on
  # disk for the next one. The agent is never started before this point.
  #
  # Goes through the Server API because in 5.0.0 the manager ships no local CLI that removes agents
  # (manage_agents is only installed with the agent). older_than=0s because the default (7d) skips an
  # agent registered minutes ago; purge drops its key instead of keeping it as removed.
  #
  # Not fatal: if the removal fails, the agent's enrollment is rejected as a duplicate and the agent
  # stays down, which is better than stopping before the dashboard starts. The warning says why.
  #
  # client.keys is truncated rather than deleted so the file keeps the ownership and mode the agent
  # package gave it; the bootstrap only looks at its size.
  if [ ! -f "${wazuh_agent_client_keys}" ]; then
      return
  fi

  local agent_id password jwt response
  agent_id=$(awk 'NR == 1 { print $1 }' "${wazuh_agent_client_keys}")
  if [ -n "${agent_id}" ] && ! [[ "${agent_id}" =~ ^[0-9]+$ ]]; then
      logger -w "Ignoring an unexpected agent ID in client.keys: ${agent_id}"
  elif [ -n "${agent_id}" ]; then
      logger "Removing agent ${agent_id}, enrolled by an earlier run of this script, from the manager"
      # Password and JWT reach curl through its standard input, never argv (see http_status()).
      password=$(get_credential "${wazuh_manager_api_key}")
      jwt=$(printf 'user = "%s:%s"\n' "${wazuh_manager_api_user}" "${password}" \
        | curl -s -k -K - -X POST --max-time 120 "https://localhost:55000/security/user/authenticate?raw=true")
      response=$(printf 'header = "Authorization: Bearer %s"\n' "${jwt}" \
        | curl -s -k -K - -X DELETE --max-time 120 \
          "https://localhost:55000/agents?agents_list=${agent_id}&status=all&older_than=0s&purge=true")
      if grep -qE '"total_affected_items": ?1' <<< "${response}"; then
          logger "Agent ${agent_id} removed"
      else
          logger -w "Could not remove agent ${agent_id}; its enrollment will be rejected as a duplicate: ${response}"
      fi
  fi

  : > "${wazuh_agent_client_keys}"
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
  # certificate this VM issued for itself moments earlier in install_credentials(). Its 30-day
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

function wait_for_network_address() {
  # The resolvers take the SANs from the default-route interfaces when --install runs, and issue a
  # pair only once. A remoted.pem issued before the address is up names the host name and loopback
  # only: agents cannot enroll by IP, and the manager refuses to mint a token for it (ERROR 9025).
  # Confirmed on an OVA booted with its link down for 60 s (wazuh-virtual-machines#1039, TC-05).
  # The unit waits for network-online.target; this covers a DHCP lease that comes later. With no
  # address after the wait, carry on (an isolated VM still works locally) but say how to fix it.
  local retries=0 max_retries=60 wait_time=5
  while [[ -z "$(hostname -I | tr -d ' ')" ]] && [[ "${retries}" -lt "${max_retries}" ]]; do
    logger -w "No network address available yet for the certificates' SANs, waiting ${wait_time} seconds"
    sleep "${wait_time}"
    retries=$((retries + 1))
  done
  if [[ -z "$(hostname -I | tr -d ' ')" ]]; then
    logger -e "No network address after $((max_retries * wait_time)) seconds: the certificates will name this VM by host name and loopback only. Agents cannot enroll by IP until the manager pairs are reissued (see the OVA documentation)."
  fi
}

function run_or_die() {
  # $1: error message, rest: the command to run. Fail loud instead of carrying on half configured.
  local error_message="$1"
  shift
  if ! "$@"; then
    logger -e "${error_message}"
    exit 1
  fi
}

function install_credentials() {
  # Every package's `resolve-credentials --install`: each mints its own CA, issues its pairs with
  # this VM's addresses and publishes its export/. Safe to run again after a failed first boot: a
  # resolver keeps a complete pair and a CA it finds.
  wait_for_network_address
  # No sudo: the unit already runs as root, and SELinux denies the starter (init_t) running sudo
  # (sudo_exec_t); it only worked because the OVA runs SELinux in permissive mode.
  local resolver
  for resolver in "${credential_resolvers[@]}"; do
    logger "Running ${resolver} --install"
    run_or_die "${resolver} --install failed" "${resolver}" --install < /dev/null
  done
  # remoted remembers the build-time root-ca.pem; replacing it without publishing makes remoted log
  # "changed outside the tool and is not published" and announce ca_generation 0 to the agents
  # (wazuh-virtual-machines#1022). stamp publishes the new bundle as is; it only needs the files, not
  # a running manager, and checks the bundle against remoted.pem.
  run_or_die "Failed to publish this VM's CA with wazuh-manager-certs stamp" \
      "${wazuh_manager_certs_bin}" stamp
}

function clean_configuration(){
  logger "Cleaning configuration files"
  eval "rm -rf /var/log/wazuh-starter.log"
  # Disable the units before removing them, so no dangling symlink is left in the *.wants directories.
  systemctl --quiet disable wazuh-starter.timer wazuh-starter.service 2>/dev/null || true
  eval "rm -f /etc/.wazuh-starter.sh /etc/systemd/system/wazuh-starter.service /etc/systemd/system/wazuh-starter.timer"
  systemctl daemon-reload || true
  # Each package's export/credentials.env is kept: it is where the user reads the generated passwords
  # from, and the peers import from it.
}


###########################################
# Main
###########################################

logger "Starting Wazuh services in order"

# Certificates first: the packages never issue them outside `--install`.
reset_enrollment_state
install_credentials

# Then strictly in order, never in parallel: each package resolves its credentials when its service
# starts (`--prestart`), importing what it needs from its peers' export/, and refuses to start
# (MISSING) if a peer has not published it yet.
starter_service wazuh-indexer
wait_for_indexer
run_indexer_security_init
verify_indexer

starter_service wazuh-manager
verify_manager
reset_agent_identity
# Minting goes through the manager's local authd socket, so it has to happen after the manager is
# up; the bootstrap only looks for the token file at the agent's first start, so it has to happen
# before the agent starts.
set_agent_enrollment_token

starter_service wazuh-agent

starter_service wazuh-dashboard
verify_dashboard
systemctl enable wazuh-indexer
systemctl enable wazuh-manager
systemctl enable wazuh-agent
systemctl enable wazuh-dashboard

clean_configuration
