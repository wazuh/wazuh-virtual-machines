#!/bin/bash
# Removes every credential, certificate and CA the image build generated, so that no two instances
# deployed from a published AMI or OVA share any of them (wazuh-virtual-machines#973).
#
# The Wazuh 5.0 packages resolve their own credentials in their postinst (`resolve-credentials
# --install`): each mints its own CA in /etc/<package>/ca/, issues its pairs, publishes what its
# peers need in /etc/<package>/export/ and imports its peers' (wazuh/internal-devel-requests#7048).
# Each package ships `resolve-credentials --clear` for exactly this case: it removes what that
# package made, so the next `--install` -- the first boot of the deployed instance -- starts from
# nothing.
#
# Must run as root with every Wazuh service stopped: each `--clear` refuses to run while its
# component is up.
#
# Exits non-zero, naming what is left, if anything built into the image survives.
#
# WORKAROUND (until the manager's --clear covers it; remove it then, the verification below keeps
# checking the result): remove the Server API JWT signing keypair.

set -euo pipefail

INDEXER_RESOLVER="/usr/share/wazuh-indexer/bin/resolve-credentials.sh"
MANAGER_RESOLVER="/var/wazuh-manager/bin/wazuh-manager-resolve-credentials"
MANAGER_HOME="/var/wazuh-manager"
DASHBOARD_RESOLVER="/usr/share/wazuh-dashboard/bin/resolve-credentials"

INDEXER_CONF="/etc/wazuh-indexer"
MANAGER_CONF="/etc/wazuh-manager"
DASHBOARD_CONF="/etc/wazuh-dashboard"
INDEXER_INTERNAL_USERS="${INDEXER_CONF}/opensearch-security/internal_users.yml"
INDEXER_MARKER="/var/lib/wazuh-indexer/.initialized"
MANAGER_RBAC_DB="${MANAGER_HOME}/api/configuration/security/rbac.db"
MANAGER_KEYSTORE_DIR="${MANAGER_HOME}/queue/keystore"
MANAGER_API_JWT_PRIVATE="${MANAGER_HOME}/api/configuration/security/private_key.pem"
MANAGER_API_JWT_PUBLIC="${MANAGER_HOME}/api/configuration/security/public_key.pem"
INDEXER_KEYTOOL="/usr/share/wazuh-indexer/jdk/bin/keytool"
INDEXER_JDK_CA_ALIAS="wazuh-root-ca"
INDEXER_JDK_CACERTS_PASS="changeit"

jdk_ca_present() {
    "${INDEXER_KEYTOOL}" -list -cacerts -storepass "${INDEXER_JDK_CACERTS_PASS}" \
        -alias "${INDEXER_JDK_CA_ALIAS}" > /dev/null 2>&1
}

echo "Clearing the credentials resolved at build time"
# stdin from /dev/null: nothing run here may read input meant for this script. The indexer's
# --clear also puts the ${WAZUH_INDEXER_*_PASSWORD} placeholders back in internal_users.yml and
# takes its CA out of the JDK truststore; the manager's also empties rbac.db and its keystore.
"${INDEXER_RESOLVER}" --clear < /dev/null
"${MANAGER_RESOLVER}" --clear -H "${MANAGER_HOME}" < /dev/null
"${DASHBOARD_RESOLVER}" --clear < /dev/null

# WORKAROUND -- remove once the manager's --clear removes it itself.
#
# The JWT signing keypair is created the first time the API issues or checks a token, and --clear
# leaves it in place, so every instance would sign its tokens with the same key. The API creates a
# new keypair when neither file exists (they go together: it refuses to start with only one).
echo "Removing the Server API JWT signing keypair created at build time"
rm -f "${MANAGER_API_JWT_PRIVATE}" "${MANAGER_API_JWT_PUBLIC}"

echo "Verifying that nothing resolved at build time is left"
leftovers=()
# No package uses /etc/wazuh since RC 2; one left behind would be an older package's.
[ -e /etc/wazuh ] && leftovers+=("/etc/wazuh")
[ -e "${INDEXER_MARKER}" ] && leftovers+=("${INDEXER_MARKER}")
[ -e "${MANAGER_RBAC_DB}" ] && leftovers+=("${MANAGER_RBAC_DB}")
for dir in "${MANAGER_KEYSTORE_DIR}" \
           "${INDEXER_CONF}/ca" "${INDEXER_CONF}/export" \
           "${MANAGER_CONF}/ca" "${MANAGER_CONF}/export" \
           "${DASHBOARD_CONF}/ca" "${DASHBOARD_CONF}/export"; do
    if [ -d "${dir}" ] && [ -n "$(find "${dir}" -mindepth 1 -print -quit)" ]; then
        leftovers+=("${dir} (not empty)")
    fi
done
for key in WAZUH_INDEXER_ADMIN_PASSWORD WAZUH_INDEXER_KIBANASERVER_PASSWORD WAZUH_INDEXER_MANAGER_PASSWORD; do
    grep -q "\${${key}}" "${INDEXER_INTERNAL_USERS}" || leftovers+=("${INDEXER_INTERNAL_USERS} (no \${${key}} placeholder)")
done
# The manager's indexer-ca.pem and indexer-connector*.pem are the pair the indexer issued it (D5),
# imported from the indexer's export/.
for cert in "${INDEXER_CONF}"/certs/* "${DASHBOARD_CONF}"/certs/* \
            "${MANAGER_CONF}"/certs/remoted*.pem "${MANAGER_CONF}"/certs/apid*.pem \
            "${MANAGER_CONF}"/certs/root-ca.pem "${MANAGER_CONF}"/certs/indexer-ca.pem \
            "${MANAGER_CONF}"/certs/indexer-connector*.pem \
            "${MANAGER_API_JWT_PRIVATE}" "${MANAGER_API_JWT_PUBLIC}"; do
    [ -e "${cert}" ] && leftovers+=("${cert}")
done
jdk_ca_present && leftovers+=("indexer JDK truststore (cacerts, alias ${INDEXER_JDK_CA_ALIAS})")

if [ "${#leftovers[@]}" -gt 0 ]; then
    echo "ERROR: the image still holds material resolved at build time:" >&2
    printf '  %s\n' "${leftovers[@]}" >&2
    exit 1
fi

echo "Build-time credentials, certificates and CA removed"
