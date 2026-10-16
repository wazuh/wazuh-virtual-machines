from pathlib import Path

import pytest

from configurer.core.utils import (
    CredentialKey,
    credential_shell_expression,
    credentials_file_for,
    indexer_request_command,
    parse_credentials,
    purge_build_credentials_command,
    read_credential,
)
from configurer.core.utils.credentials import PURGE_BUILD_CREDENTIALS_SCRIPT

CREDENTIALS_ENV = """# >>> wazuh generated — do not edit <<<
# Editing a value here does not change the deployment.
WAZUH_INDEXER_ADMIN_PASSWORD="Ab1.cdefghijklmnopqrstuvwxyz:@%^"
WAZUH_INDEXER_KIBANASERVER_PASSWORD='Kb2,single-quoted_value'
WAZUH_INDEXER_MANAGER_PASSWORD=Mg3-unquoted~value
WAZUH_MANAGER_WUI_PASSWORD=
# >>> end wazuh generated <<<
WAZUH_INDEXER_MANAGER_PASSWORD="Mg4=last-assignment-wins"
"""


def test_parse_credentials_unquotes_values_and_keeps_the_last_assignment():
    credentials = parse_credentials(CREDENTIALS_ENV)

    assert credentials[CredentialKey.INDEXER_ADMIN] == "Ab1.cdefghijklmnopqrstuvwxyz:@%^"
    assert credentials[CredentialKey.INDEXER_KIBANASERVER] == "Kb2,single-quoted_value"
    assert credentials[CredentialKey.INDEXER_MANAGER] == "Mg4=last-assignment-wins"
    assert credentials[CredentialKey.MANAGER_WUI] == ""
    assert CredentialKey.MANAGER_API not in credentials


def test_read_credential(tmp_path: Path):
    credentials_file = tmp_path / "credentials.env"
    credentials_file.write_text(CREDENTIALS_ENV)

    assert read_credential(CredentialKey.INDEXER_ADMIN, credentials_file) == "Ab1.cdefghijklmnopqrstuvwxyz:@%^"


@pytest.mark.parametrize("key", [CredentialKey.MANAGER_WUI, CredentialKey.MANAGER_API])
def test_read_credential_missing_or_empty_names_the_key_only(tmp_path: Path, key):
    credentials_file = tmp_path / "credentials.env"
    credentials_file.write_text(CREDENTIALS_ENV)

    with pytest.raises(KeyError) as error:
        read_credential(key, credentials_file)

    assert str(key) in str(error.value)
    assert "Ab1." not in str(error.value)


def test_credential_shell_expression_reads_the_key_from_the_file():
    expression = credential_shell_expression(CredentialKey.INDEXER_ADMIN)

    assert expression.startswith("$(")
    assert "sudo sed -n 's/^WAZUH_INDEXER_ADMIN_PASSWORD=//p' /etc/wazuh-indexer/export/credentials.env" in expression


@pytest.mark.parametrize(
    "key, path",
    [
        (CredentialKey.INDEXER_ADMIN, "/etc/wazuh-indexer/export/credentials.env"),
        (CredentialKey.INDEXER_KIBANASERVER, "/etc/wazuh-indexer/export/credentials.env"),
        (CredentialKey.INDEXER_MANAGER, "/etc/wazuh-indexer/export/credentials.env"),
        (CredentialKey.MANAGER_API, "/etc/wazuh-manager/export/credentials.env"),
        (CredentialKey.MANAGER_WUI, "/etc/wazuh-manager/export/credentials.env"),
    ],
)
def test_each_key_is_read_from_its_owner_export(key, path):
    # The indexer publishes its users' passwords, the manager the Server API ones (RC 2).
    assert credentials_file_for(key) == Path(path)
    assert f" {path} " in credential_shell_expression(key)


def test_indexer_request_command_sends_the_password_through_stdin():
    command = indexer_request_command(method="DELETE", path="wazuh-*")

    assert "-K -" in command
    assert "-X DELETE 'https://127.0.0.1:9200/wazuh-*'" in command
    assert "printf 'user = \"%s:%s\"\\n' 'admin' \"$WAZUH_PW\"" in command
    assert "-u " not in command
    assert "admin:admin" not in command


def test_purge_build_credentials_command_runs_the_script_from_a_file_not_stdin():
    command = purge_build_credentials_command()

    # Written to a temporary file and run from there, with stdin from /dev/null: fed through
    # `bash -s`, a command reading stdin would swallow the rest of the script.
    assert command.startswith('WAZUH_PURGE_SCRIPT="$(mktemp)" || exit 1\n')
    assert "cat > \"${WAZUH_PURGE_SCRIPT}\" <<'WAZUH_PURGE_BUILD_CREDENTIALS'\n" in command
    assert PURGE_BUILD_CREDENTIALS_SCRIPT.read_text() in command
    assert 'sudo bash "${WAZUH_PURGE_SCRIPT}" < /dev/null\n' in command
    assert "bash -s" not in command
    assert command.rstrip().endswith('exit "${WAZUH_PURGE_RC}"')


def test_purge_build_credentials_script_clears_every_component():
    script = PURGE_BUILD_CREDENTIALS_SCRIPT.read_text()

    assert '"${INDEXER_RESOLVER}" --clear' in script
    assert '"${MANAGER_RESOLVER}" --clear -H "${MANAGER_HOME}"' in script
    assert '"${DASHBOARD_RESOLVER}" --clear' in script
    # The indexer's --clear restores the placeholders and untrusts its CA itself (RC 2): no workaround.
    assert "awk" not in script
    assert "-delete -cacerts" not in script
    # /etc/wazuh is no package's any more: checked for, never removed.
    assert "rm -rf" not in script
    assert '[ -e /etc/wazuh ] && leftovers+=("/etc/wazuh")' in script


def test_purge_build_credentials_script_checks_every_package_ca_export_and_certs():
    script = PURGE_BUILD_CREDENTIALS_SCRIPT.read_text()

    for package in ("INDEXER", "MANAGER", "DASHBOARD"):
        assert f'"${{{package}_CONF}}/ca" "${{{package}_CONF}}/export"' in script
    # D5: the client pair the indexer issued to the manager, imported from its export/.
    assert '"${MANAGER_CONF}"/certs/indexer-connector*.pem' in script
    assert '"${MANAGER_CONF}"/certs/indexer-ca.pem' in script
    assert '"${MANAGER_CONF}"/certs/apid*.pem' in script
    for key in (CredentialKey.INDEXER_ADMIN, CredentialKey.INDEXER_KIBANASERVER, CredentialKey.INDEXER_MANAGER):
        assert str(key) in script
    assert "jdk_ca_present && leftovers+=" in script


def test_purge_build_credentials_script_removes_the_jwt_keypair():
    script = PURGE_BUILD_CREDENTIALS_SCRIPT.read_text()

    # Workaround: the manager's --clear removes apid.pem but not the JWT signing keypair.
    assert 'rm -f "${MANAGER_API_JWT_PRIVATE}" "${MANAGER_API_JWT_PUBLIC}"' in script
    assert 'MANAGER_API_JWT_PRIVATE="${MANAGER_HOME}/api/configuration/security/private_key.pem"' in script
    assert '"${MANAGER_API_JWT_PRIVATE}" "${MANAGER_API_JWT_PUBLIC}"; do' in script


def test_purge_build_credentials_script_gives_no_stdin_to_the_resolvers():
    script = PURGE_BUILD_CREDENTIALS_SCRIPT.read_text()

    assert '"${INDEXER_RESOLVER}" --clear < /dev/null' in script
    assert '"${MANAGER_RESOLVER}" --clear -H "${MANAGER_HOME}" < /dev/null' in script
    assert '"${DASHBOARD_RESOLVER}" --clear < /dev/null' in script
