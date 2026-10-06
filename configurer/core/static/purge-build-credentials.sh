#!/bin/bash
# Removes every credential, certificate and CA the image build generated, so that no two instances
# deployed from a published AMI or OVA share any of them (wazuh-virtual-machines#973).
#
# The Wazuh 5.0 packages resolve their own credentials in their postinst (`resolve-credentials
# --install`), so building the image leaves this host's passwords, a bootstrap CA and issued
# certificates behind. Each package ships `resolve-credentials --clear` for exactly this case: it
# removes what that component owns or stores, so its next `--prestart` -- the first boot of the
# deployed instance -- resolves from nothing.
#
# Must run as root with every Wazuh service stopped: each `--clear` refuses to run while its
# component is up.
#
# Exits non-zero, naming what is left, if anything built into the image survives.
#
# WORKAROUNDS (until the packages' --clear covers them; remove them then, the verification below
# keeps checking the result):
#   1. Indexer: restore the ${WAZUH_INDEXER_*_PASSWORD} placeholders in internal_users.yml.
#   2. Manager: remove the Server API TLS pair (apid.pem/apid-key.pem) and JWT signing keypair.
#   3. Indexer: remove the build CA the postinst imported into the JDK truststore (cacerts).
#   4. Manager: remove the Server API log written at build time (wazuh/wazuh#40053).

set -euo pipefail

INDEXER_RESOLVER="/usr/share/wazuh-indexer/bin/resolve-credentials.sh"
MANAGER_RESOLVER="/var/wazuh-manager/bin/wazuh-manager-resolve-credentials"
MANAGER_HOME="/var/wazuh-manager"
DASHBOARD_RESOLVER="/usr/share/wazuh-dashboard/bin/resolve-credentials"

WAZUH_BASE_DIR="/etc/wazuh"
INDEXER_INTERNAL_USERS="/etc/wazuh-indexer/opensearch-security/internal_users.yml"
INDEXER_MARKER="/var/lib/wazuh-indexer/.initialized"
MANAGER_RBAC_DB="${MANAGER_HOME}/api/configuration/security/rbac.db"
MANAGER_KEYSTORE_DIR="${MANAGER_HOME}/queue/keystore"
MANAGER_API_CERT="${MANAGER_HOME}/etc/certs/apid.pem"
MANAGER_API_KEY="${MANAGER_HOME}/etc/certs/apid-key.pem"
MANAGER_API_JWT_PRIVATE="${MANAGER_HOME}/api/configuration/security/private_key.pem"
MANAGER_API_JWT_PUBLIC="${MANAGER_HOME}/api/configuration/security/public_key.pem"
MANAGER_API_LOG="${MANAGER_HOME}/logs/api.log"
INDEXER_KEYTOOL="/usr/share/wazuh-indexer/jdk/bin/keytool"
INDEXER_JDK_CA_ALIAS="wazuh-root-ca"
INDEXER_JDK_CACERTS_PASS="changeit"

jdk_ca_present() {
    "${INDEXER_KEYTOOL}" -list -cacerts -storepass "${INDEXER_JDK_CACERTS_PASS}" \
        -alias "${INDEXER_JDK_CA_ALIAS}" > /dev/null 2>&1
}

echo "Clearing the credentials resolved at build time"
# stdin from /dev/null: nothing run here may read input meant for this script.
"${INDEXER_RESOLVER}" --clear < /dev/null
"${MANAGER_RESOLVER}" --clear -H "${MANAGER_HOME}" < /dev/null
"${DASHBOARD_RESOLVER}" --clear < /dev/null

# WORKAROUND 1 -- remove once the indexer's --clear restores them itself.
#
# The indexer's --clear does not touch internal_users.yml: the bcrypt digests its --install wrote
# over the ${WAZUH_INDEXER_*_PASSWORD} placeholders stay there. Its --prestart only writes a digest
# where it finds the placeholder, so on first boot it would publish new passwords to
# credentials.env while the indexer kept accepting the build-time ones, and every account would
# fail with 401. Putting the three placeholders back is what lets the first boot's --prestart write
# digests that match what it publishes. Only the `hash:` line of the three indexer-owned users is
# rewritten; the rest of the file, its owner and its mode are kept.
echo "Restoring the password placeholders in ${INDEXER_INTERNAL_USERS}"
awk '
    /^[A-Za-z0-9_-]+:[[:space:]]*$/ { user = $1; sub(":", "", user) }
    /^[[:space:]]+hash:/ {
        key = ""
        if (user == "admin")         key = "WAZUH_INDEXER_ADMIN_PASSWORD"
        if (user == "kibanaserver")  key = "WAZUH_INDEXER_KIBANASERVER_PASSWORD"
        if (user == "wazuh-manager") key = "WAZUH_INDEXER_MANAGER_PASSWORD"
        if (key != "") { print "  hash: \"${" key "}\""; next }
    }
    { print }
' "${INDEXER_INTERNAL_USERS}" > "${INDEXER_INTERNAL_USERS}.tmp"
cat "${INDEXER_INTERNAL_USERS}.tmp" > "${INDEXER_INTERNAL_USERS}"
rm -f "${INDEXER_INTERNAL_USERS}.tmp"

# WORKAROUND 2 -- remove once the manager's --clear removes it itself.
#
# The Server API TLS pair is created when the manager first starts during the build, and the JWT
# signing keypair the first time the API issues or checks a token; --clear leaves both in place, so
# every instance would serve its API with the same TLS key and sign its tokens with the same key. The
# manager creates a new TLS pair on its next start, and the API a new keypair when neither file
# exists (they go together: the API refuses to start with only one of them).
echo "Removing the Server API TLS pair and JWT signing keypair created at build time"
rm -f "${MANAGER_API_CERT}" "${MANAGER_API_KEY}" "${MANAGER_API_JWT_PRIVATE}" "${MANAGER_API_JWT_PUBLIC}"

# WORKAROUND 3 -- remove once the indexer's --clear removes it itself.
#
# The indexer postinst imports the CA it minted at install time into the bundled JDK truststore as
# "wazuh-root-ca", and --clear leaves it there: every instance would trust the build CA. First boot
# imports that instance's own CA under the same alias, as a fresh package install would.
if jdk_ca_present; then
    echo "Removing the build CA from the indexer JDK truststore (${INDEXER_JDK_CA_ALIAS})"
    "${INDEXER_KEYTOOL}" -delete -cacerts -storepass "${INDEXER_JDK_CACERTS_PASS}" \
        -alias "${INDEXER_JDK_CA_ALIAS}" < /dev/null
fi

# WORKAROUND 4 -- remove once wazuh/wazuh#40053 is fixed in the manager (planned for RC2).
#
# The API rotates api.log at midnight, based on the file's mtime. An image booted on a later day
# than it was built finds a build-time api.log, so the API's first log record rotates it while the
# API still runs as root: the new api.log is created root:root 0644, the API cannot open it once it
# drops privileges, and it exits silently (nothing listens on 55000). Without the file, the API
# creates it on first boot with the right owner and a fresh mtime, so no rotation is pending.
echo "Removing the Server API log written at build time"
rm -f "${MANAGER_API_LOG}"

# --clear leaves /etc/wazuh behind: credentials.env with an empty managed block, the lock file and
# an empty ca/ directory. A published image must carry none of them; the packages recreate the
# directory on first boot.
echo "Removing ${WAZUH_BASE_DIR}"
rm -rf "${WAZUH_BASE_DIR}"

echo "Verifying that nothing resolved at build time is left"
leftovers=()
[ -e "${WAZUH_BASE_DIR}" ] && leftovers+=("${WAZUH_BASE_DIR}")
[ -e "${INDEXER_MARKER}" ] && leftovers+=("${INDEXER_MARKER}")
[ -e "${MANAGER_RBAC_DB}" ] && leftovers+=("${MANAGER_RBAC_DB}")
if [ -d "${MANAGER_KEYSTORE_DIR}" ] && [ -n "$(find "${MANAGER_KEYSTORE_DIR}" -mindepth 1 -print -quit)" ]; then
    leftovers+=("${MANAGER_KEYSTORE_DIR} (not empty)")
fi
for key in WAZUH_INDEXER_ADMIN_PASSWORD WAZUH_INDEXER_KIBANASERVER_PASSWORD WAZUH_INDEXER_MANAGER_PASSWORD; do
    grep -q "\${${key}}" "${INDEXER_INTERNAL_USERS}" || leftovers+=("${INDEXER_INTERNAL_USERS} (no \${${key}} placeholder)")
done
for cert in /etc/wazuh-indexer/certs/* /etc/wazuh-dashboard/certs/* \
            "${MANAGER_HOME}"/etc/certs/remoted*.pem "${MANAGER_HOME}"/etc/certs/indexer-connector*.pem \
            "${MANAGER_HOME}"/etc/certs/root-ca.pem "${MANAGER_API_CERT}" "${MANAGER_API_KEY}" \
            "${MANAGER_API_JWT_PRIVATE}" "${MANAGER_API_JWT_PUBLIC}" "${MANAGER_API_LOG}"; do
    [ -e "${cert}" ] && leftovers+=("${cert}")
done
jdk_ca_present && leftovers+=("indexer JDK truststore (cacerts, alias ${INDEXER_JDK_CA_ALIAS})")

if [ "${#leftovers[@]}" -gt 0 ]; then
    echo "ERROR: the image still holds material resolved at build time:" >&2
    printf '  %s\n' "${leftovers[@]}" >&2
    exit 1
fi

echo "Build-time credentials, certificates and CA removed"
