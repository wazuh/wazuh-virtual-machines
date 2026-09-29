from pathlib import Path

import pytest

from configurer.core.utils import (
    CredentialKey,
    credential_shell_expression,
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
    assert "sudo sed -n 's/^WAZUH_INDEXER_ADMIN_PASSWORD=//p' /etc/wazuh/credentials.env" in expression


def test_indexer_request_command_sends_the_password_through_stdin():
    command = indexer_request_command(method="DELETE", path="wazuh-*")

    assert "-K -" in command
    assert "-X DELETE 'https://127.0.0.1:9200/wazuh-*'" in command
    assert "printf 'user = \"%s:%s\"\\n' 'admin' \"$WAZUH_PW\"" in command
    assert "-u " not in command
    assert "admin:admin" not in command


def test_purge_build_credentials_command_feeds_the_script_on_stdin():
    command = purge_build_credentials_command()

    assert command.startswith("sudo bash -s <<'WAZUH_PURGE_BUILD_CREDENTIALS'\n")
    assert command.rstrip().endswith("WAZUH_PURGE_BUILD_CREDENTIALS")
    assert PURGE_BUILD_CREDENTIALS_SCRIPT.read_text() in command


def test_purge_build_credentials_script_clears_every_component_and_restores_the_placeholders():
    script = PURGE_BUILD_CREDENTIALS_SCRIPT.read_text()

    assert '"${INDEXER_RESOLVER}" --clear' in script
    assert '"${MANAGER_RESOLVER}" --clear -H "${MANAGER_HOME}"' in script
    assert '"${DASHBOARD_RESOLVER}" --clear' in script
    for key in (CredentialKey.INDEXER_ADMIN, CredentialKey.INDEXER_KIBANASERVER, CredentialKey.INDEXER_MANAGER):
        assert str(key) in script
    assert 'rm -rf "${WAZUH_BASE_DIR}"' in script


def test_purge_build_credentials_script_removes_the_api_pair_and_the_jdk_truststore_ca():
    script = PURGE_BUILD_CREDENTIALS_SCRIPT.read_text()

    # Workaround 2: the Server API TLS pair created at build time.
    assert 'rm -f "${MANAGER_API_CERT}" "${MANAGER_API_KEY}"' in script
    assert 'MANAGER_API_CERT="${MANAGER_HOME}/etc/certs/apid.pem"' in script
    # Workaround 3: the build CA imported by the indexer postinst into the JDK truststore.
    assert 'INDEXER_JDK_CA_ALIAS="wazuh-root-ca"' in script
    assert '-delete -keystore "${INDEXER_JDK_CACERTS}"' in script
    # Both are part of the leftovers verification.
    assert '"${MANAGER_API_CERT}" "${MANAGER_API_KEY}"; do' in script
    assert 'jdk_ca_present && leftovers+=' in script
