from enum import StrEnum
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from configurer.core.models.certificates_manager import CertsManager
from configurer.core.utils import ComponentCertsConfigParameter, ComponentCertsDirectory
from configurer.core.utils.enums import ComponentConfigFile
from utils import Component

RAW_CONFIG_PATH = Path("/path/to/config.yml")
CERTS_TOOL_PATH = Path("/path/to/certs-tool.sh")


class MockConfigParameters(StrEnum):
    # Wazuh Server
    WAZUH_MANAGER_KEY = "manager.test.key"
    WAZUH_MANAGER_CERT = "manager.test.cert"
    WAZUH_MANAGER_CA = "manager.test.ca"
    # Wazuh Indexer
    WAZUH_INDEXER_KEY = "indexer.test.key"
    WAZUH_INDEXER_CERT = "indexer.test.cert"
    WAZUH_INDEXER_CA = "indexer.test.ca"
    # Wazuh Dashboard
    WAZUH_DASHBOARD_KEY = "dashboard.test.key"
    WAZUH_DASHBOARD_CERT = "dashboard.test.cert"
    WAZUH_DASHBOARD_CA = "dashboard.test.ca"


@pytest.fixture
def expected_config_query():
    return f"""
            sudo yq -i '.nodes.indexer[0].name = \"{Component.WAZUH_INDEXER}\" |
            .nodes.indexer[0].ip = "127.0.0.1" | .nodes.indexer[0].ip style="double" |
            .nodes.manager[0].name = \"{Component.WAZUH_MANAGER}\" |
            .nodes.manager[0].ip = "127.0.0.1" | .nodes.manager[0].ip style="double" |
            .nodes.dashboard[0].name = \"{Component.WAZUH_DASHBOARD}\" |
            .nodes.dashboard[0].ip = "127.0.0.1" | .nodes.dashboard[0].ip style="double"
            ' {RAW_CONFIG_PATH}
            """.replace("\n", "").replace(" ", "")


@pytest.fixture
def mock_exec_command():
    with patch("configurer.core.models.certificates_manager.exec_command") as mock_exec_command:
        mock_exec_command.return_value = ("", "")
        yield mock_exec_command


@pytest.mark.parametrize("client", [None, MagicMock()])
@patch("configurer.core.models.certificates_manager.CertsManager._set_config_file_values")
def test_init_with_valid_arguments(mock_set_config_file_values, client):
    raw_config_path = Path("/path/to/config.yml")
    certs_tool_path = Path("/path/to/certs-tool.sh")

    certs_manager = CertsManager(raw_config_path=raw_config_path, certs_tool_path=certs_tool_path, client=client)

    assert certs_manager.certs_tool_path == certs_tool_path
    assert Component.WAZUH_INDEXER in certs_manager.components_certs_default_name
    assert Component.WAZUH_MANAGER in certs_manager.components_certs_default_name
    assert Component.WAZUH_DASHBOARD in certs_manager.components_certs_default_name
    assert Component.WAZUH_MANAGER in certs_manager.components_certs_config_keys
    assert Component.WAZUH_INDEXER in certs_manager.components_certs_config_keys
    assert Component.WAZUH_DASHBOARD in certs_manager.components_certs_config_keys
    mock_set_config_file_values.assert_called_once_with(raw_config_path=raw_config_path, client=client)


@patch("configurer.core.models.certificates_manager.CertsManager._set_config_file_values")
def test_init_sets_default_cert_names(mock_set_config_file_values):
    raw_config_path = Path("/path/to/config.yml")
    certs_tool_path = Path("/path/to/certs-tool.sh")

    certs_manager = CertsManager(raw_config_path=raw_config_path, certs_tool_path=certs_tool_path)

    assert (
        certs_manager.components_certs_default_name[Component.WAZUH_INDEXER]["cert"] == f"{Component.WAZUH_INDEXER}.pem"
    )
    assert (
        certs_manager.components_certs_default_name[Component.WAZUH_MANAGER]["key"]
        == f"{Component.WAZUH_MANAGER}-key.pem"
    )
    assert certs_manager.components_certs_default_name[Component.WAZUH_DASHBOARD]["ca"] == "root-ca.pem"
    mock_set_config_file_values.assert_called_once_with(raw_config_path=raw_config_path, client=None)


def test_set_config_file_values_success(mock_exec_command, mock_logger, expected_config_query):
    CertsManager(raw_config_path=RAW_CONFIG_PATH, certs_tool_path=CERTS_TOOL_PATH)

    response = mock_exec_command.call_args.kwargs["command"].replace("\n", "").replace(" ", "")
    mock_exec_command.assert_called_once()
    assert response == expected_config_query

    mock_logger.debug.assert_called_once_with("Setting config file values")


def test_set_config_file_values_error(mock_exec_command, mock_logger, expected_config_query):
    mock_exec_command.return_value = ("", "Error: yq command failed")
    with pytest.raises(Exception, match="Error while setting config file values: Error: yq command failed"):
        CertsManager(raw_config_path=RAW_CONFIG_PATH, certs_tool_path=CERTS_TOOL_PATH)

    response = mock_exec_command.call_args.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_exec_command.assert_called_once()
    assert response == expected_config_query

    mock_logger.error.assert_called_once_with("Error while setting config file values")


@pytest.mark.parametrize(
    "raw_name, format_name",
    [("/path/to/wazuh-manager.pem", "wazuh-manager.pem"), ('["/path/to/wazuh-dashboard.pem"]', "wazuh-dashboard.pem")],
)
def test_get_name_cert_from_key_success(raw_name, format_name, mock_exec_command, mock_logger):
    mock_exec_command.return_value = (raw_name, "")
    certs_manager = CertsManager(raw_config_path=RAW_CONFIG_PATH, certs_tool_path=CERTS_TOOL_PATH)

    cert_name = certs_manager._get_cert_name_from_key("test.key", "/path/test/file", flattened_key=False)

    expected_command = "sudo yq '.test.key' /path/test/file".replace("\n", "").replace(" ", "")
    command_response = mock_exec_command.call_args.kwargs["command"].replace("\n", "").replace(" ", "")
    mock_exec_command.assert_called()
    assert command_response == expected_command

    assert cert_name == format_name


def test_get_name_cert_from_key_with_flattened_key_success(mock_exec_command, mock_logger):
    mock_exec_command.return_value = ("/path/to/wazuh-manager.pem", "")
    certs_manager = CertsManager(raw_config_path=RAW_CONFIG_PATH, certs_tool_path=CERTS_TOOL_PATH)

    cert_name = certs_manager._get_cert_name_from_key("test.key", "/path/test/file", flattened_key=True)

    expected_command = "sudo yq '.[\"test.key\"]' /path/test/file".replace("\n", "").replace(" ", "")
    command_response = mock_exec_command.call_args.kwargs["command"].replace("\n", "").replace(" ", "")
    mock_exec_command.assert_called()
    assert command_response == expected_command

    assert cert_name == "wazuh-manager.pem"


def test_get_name_cert_from_key_error(mock_exec_command, mock_logger):
    certs_manager = CertsManager(raw_config_path=RAW_CONFIG_PATH, certs_tool_path=CERTS_TOOL_PATH)

    mock_exec_command.return_value = ("", "Error: yq command failed")
    with pytest.raises(Exception, match="Error while executing yq query: Error: yq command failed"):
        certs_manager._get_cert_name_from_key("test.key", "/path/test/file", flattened_key=False)

    expected_command = "sudo yq '.test.key' /path/test/file".replace("\n", "").replace(" ", "")
    command_response = mock_exec_command.call_args.kwargs["command"].replace("\n", "").replace(" ", "")
    mock_exec_command.assert_called()
    assert command_response == expected_command

    mock_logger.error.assert_called_once_with("Error while executing yq query")


@pytest.mark.parametrize(
    "component, component_config_file, flattened_key, mock_cert_names, expected_result",
    [
        (
            Component.WAZUH_MANAGER,
            "/etc/wazuh-manager/wazuh-manager.yml",
            True,
            {
                "manager.test.key": "wazuh-manager-key.pem",
                "manager.test.cert": "wazuh-manager.pem",
                "manager.test.ca": "root-ca.pem",
            },
            {
                "WAZUH_MANAGER_KEY": "wazuh-manager-key.pem",
                "WAZUH_MANAGER_CERT": "wazuh-manager.pem",
                "WAZUH_MANAGER_CA": "root-ca.pem",
            },
        ),
        (
            Component.WAZUH_INDEXER,
            "/etc/wazuh-indexer/wazuh-indexer.yml",
            False,
            {
                "indexer.test.key": "wazuh-indexer-key.pem",
                "indexer.test.cert": "wazuh-indexer.pem",
                "indexer.test.ca": "root-ca.pem",
            },
            {
                "WAZUH_INDEXER_KEY": "wazuh-indexer-key.pem",
                "WAZUH_INDEXER_CERT": "wazuh-indexer.pem",
                "WAZUH_INDEXER_CA": "root-ca.pem",
            },
        ),
        (
            Component.WAZUH_DASHBOARD,
            "/etc/wazuh-dashboard/wazuh-dashboard.yml",
            True,
            {
                "dashboard.test.key": "wazuh-dashboard-key.pem",
                "dashboard.test.cert": "wazuh-dashboard.pem",
                "dashboard.test.ca": "root-ca.pem",
            },
            {
                "WAZUH_DASHBOARD_KEY": "wazuh-dashboard-key.pem",
                "WAZUH_DASHBOARD_CERT": "wazuh-dashboard.pem",
                "WAZUH_DASHBOARD_CA": "root-ca.pem",
            },
        ),
    ],
)
def test_get_certs_name_success(
    component,
    component_config_file,
    flattened_key,
    mock_cert_names,
    expected_result,
    mock_exec_command,
):
    certs_manager = CertsManager(raw_config_path=RAW_CONFIG_PATH, certs_tool_path=CERTS_TOOL_PATH)

    certs_manager.components_certs_config_keys = {  # type: ignore
        Component.WAZUH_MANAGER: [
            MockConfigParameters.WAZUH_MANAGER_KEY,
            MockConfigParameters.WAZUH_MANAGER_CERT,
            MockConfigParameters.WAZUH_MANAGER_CA,
        ],
        Component.WAZUH_INDEXER: [
            MockConfigParameters.WAZUH_INDEXER_KEY,
            MockConfigParameters.WAZUH_INDEXER_CERT,
            MockConfigParameters.WAZUH_INDEXER_CA,
        ],
        Component.WAZUH_DASHBOARD: [
            MockConfigParameters.WAZUH_DASHBOARD_KEY,
            MockConfigParameters.WAZUH_DASHBOARD_CERT,
            MockConfigParameters.WAZUH_DASHBOARD_CA,
        ],
    }

    def mock_get_cert_name_from_key(key, file, flattened_key, client):
        return mock_cert_names[key]

    certs_manager._get_cert_name_from_key = MagicMock(side_effect=mock_get_cert_name_from_key)

    certs = certs_manager._get_certs_name(
        component=component,
        component_config_file=component_config_file,
        flattened_key=flattened_key,
        client=None,
    )

    assert certs == expected_result
    for key, _value in expected_result.items():
        certs_manager._get_cert_name_from_key.assert_any_call(
            key=MockConfigParameters[key].value,
            file=component_config_file,
            flattened_key=flattened_key,
            client=None,
        )


def test_get_certs_name_empty_component_keys(mock_logger, mock_exec_command):
    certs_manager = CertsManager(raw_config_path=RAW_CONFIG_PATH, certs_tool_path=CERTS_TOOL_PATH)

    certs_manager.components_certs_config_keys = {}  # type: ignore

    certs = certs_manager._get_certs_name(
        component=Component.WAZUH_MANAGER,
        component_config_file="/path/to/file",
        flattened_key=True,
        client=None,
    )

    assert certs == {}


@pytest.mark.parametrize(
    "component, component_certs",
    [
        (
            Component.WAZUH_MANAGER,
            {
                "WAZUH_MANAGER_KEY": "wazuh-manager-key.pem",
                "WAZUH_MANAGER_CERT": "wazuh-manager.pem",
                "WAZUH_MANAGER_CA": "root-ca.pem",
            },
        ),
        (
            Component.WAZUH_INDEXER,
            {
                "WAZUH_INDEXER_KEY": "wazuh-indexer-key.pem",
                "WAZUH_INDEXER_CERT": "wazuh-indexer.pem",
                "WAZUH_INDEXER_CA": "root-ca.pem",
            },
        ),
        (
            Component.WAZUH_DASHBOARD,
            {
                "WAZUH_DASHBOARD_KEY": "wazuh-dashboard-key.pem",
                "WAZUH_DASHBOARD_CERT": "wazuh-dashboard.pem",
                "WAZUH_DASHBOARD_CA": "root-ca.pem",
            },
        ),
    ],
)
@patch("configurer.core.models.certificates_manager.CertsManager._get_certs_name")
@patch("configurer.core.models.certificates_manager.CertsManager.copy_certs_to_component_directory")
def test_generate_certificates_success(
    mock_copy_certs, mock_get_certs_name, mock_exec_command, component, component_certs, mock_logger
):
    mock_get_certs_name.return_value = component_certs
    mock_copy_certs.return_value = ("", "")

    certs_manager = CertsManager(raw_config_path=RAW_CONFIG_PATH, certs_tool_path=CERTS_TOOL_PATH)
    certs_manager.generate_certificates()

    mock_exec_command.assert_any_call(command=f"sudo bash {CERTS_TOOL_PATH} -A", client=None)

    mock_exec_command.assert_any_call(
        command=f"""
            sudo tar -cf {CERTS_TOOL_PATH.parent}/wazuh-certificates.tar -C {CERTS_TOOL_PATH.parent}/wazuh-certificates/ . && sudo rm -rf {CERTS_TOOL_PATH.parent}/wazuh-certificates
            """,
        client=None,
    )

    mock_get_certs_name.assert_any_call(
        component=component,
        component_config_file=ComponentConfigFile.WAZUH_INDEXER
        if component == Component.WAZUH_INDEXER
        else ComponentConfigFile.WAZUH_MANAGER
        if component == Component.WAZUH_MANAGER
        else ComponentConfigFile.WAZUH_DASHBOARD,
        flattened_key=component != Component.WAZUH_MANAGER,
        client=None,
    )
    mock_copy_certs.assert_any_call(
        component=component, certs_path=CERTS_TOOL_PATH.parent, certs_name=mock_get_certs_name.return_value, client=None
    )

    mock_logger.info_success.assert_any_call("Certificates generated successfully")


def test_generate_certificates_error_during_generation(mock_exec_command):
    certs_manager = CertsManager(raw_config_path=RAW_CONFIG_PATH, certs_tool_path=CERTS_TOOL_PATH)

    mock_exec_command.return_value = ("", "Error: Failed to generate certificates")
    with pytest.raises(Exception, match="Error while generating certificates: Error: Failed to generate certificates"):
        certs_manager.generate_certificates()

    # Verify certificate generation command
    mock_exec_command.assert_any_call(command=f"sudo bash {CERTS_TOOL_PATH} -A", client=None)


def test_generate_certificates_error_during_compression(mock_exec_command, mock_logger):
    certs_manager = CertsManager(raw_config_path=RAW_CONFIG_PATH, certs_tool_path=CERTS_TOOL_PATH)

    mock_exec_command.side_effect = [("", ""), ("", "Error: Failed to compress certificates")]
    with pytest.raises(Exception, match="Error while compressing certificates: Error: Failed to compress certificates"):
        certs_manager.generate_certificates()

    expected_command = f"""
        sudo tar -cf {CERTS_TOOL_PATH.parent}/wazuh-certificates.tar -C {CERTS_TOOL_PATH.parent}/wazuh-certificates/ . && sudo rm -rf {CERTS_TOOL_PATH.parent}/wazuh-certificates
        """.replace("\n", "").replace(" ", "")

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    # Verify compression command
    mock_exec_command.assert_any_call(
        command=expected_command,
        client=None,
    )


@patch("configurer.core.models.certificates_manager.CertsManager.copy_certs_to_component_directory")
@patch("configurer.core.models.certificates_manager.CertsManager._get_certs_name")
def test_generate_certificates_error_during_copy(mock_get_certs_name, mock_copy_certs, mock_exec_command, mock_logger):
    mock_get_certs_name.return_value = {
        "WAZUH_MANAGER_KEY": "wazuh-manager-key.pem",
        "WAZUH_MANAGER_CERT": "wazuh-manager.pem",
        "WAZUH_MANAGER_CA": "root-ca.pem",
    }

    certs_manager = CertsManager(raw_config_path=RAW_CONFIG_PATH, certs_tool_path=CERTS_TOOL_PATH)
    mock_copy_certs.side_effect = [("", ""), ("", "Error: Failed to copy certificates")]

    with pytest.raises(
        Exception,
        match="Error while copying certificates to wazuh manager directory: Error: Failed to copy certificates",
    ):
        certs_manager.generate_certificates()

    mock_copy_certs.assert_called()

    mock_logger.error.assert_any_call("Error while copying certificates to wazuh manager directory")


@pytest.mark.parametrize(
    "component, certs_name, expected_command",
    [
        (
            Component.WAZUH_INDEXER,
            {
                ComponentCertsConfigParameter.WAZUH_INDEXER_CERT.name: "indexer-cert.pem",
                ComponentCertsConfigParameter.WAZUH_INDEXER_KEY.name: "indexer-key.pem",
                ComponentCertsConfigParameter.WAZUH_INDEXER_CA.name: "indexer-ca.pem",
            },
            f"""
                sudo rm -rf {ComponentCertsDirectory.WAZUH_INDEXER}
                sudo mkdir -p {ComponentCertsDirectory.WAZUH_INDEXER}
                sudo tar -xf {CERTS_TOOL_PATH.parent}/wazuh-certificates.tar -C {ComponentCertsDirectory.WAZUH_INDEXER} ./indexer-cert.pem ./indexer-key.pem ./indexer-ca.pem
                sudo mv -n {ComponentCertsDirectory.WAZUH_INDEXER}/indexer-cert.pem {ComponentCertsDirectory.WAZUH_INDEXER}/indexer-cert.pem
                sudo mv -n {ComponentCertsDirectory.WAZUH_INDEXER}/indexer-key.pem {ComponentCertsDirectory.WAZUH_INDEXER}/indexer-key.pem
                sudo mv -n {ComponentCertsDirectory.WAZUH_INDEXER}/indexer-ca.pem {ComponentCertsDirectory.WAZUH_INDEXER}/indexer-ca.pem
                sudo chmod 500 {ComponentCertsDirectory.WAZUH_INDEXER}
                sudo find {ComponentCertsDirectory.WAZUH_INDEXER} -type f -exec chmod 400 {{}} \\;
                sudo chown -R wazuh-indexer:wazuh-indexer {ComponentCertsDirectory.WAZUH_INDEXER}/
            """,
        ),
        (
            Component.WAZUH_MANAGER,
            {
                ComponentCertsConfigParameter.WAZUH_MANAGER_CERT.name: "server-cert.pem",
                ComponentCertsConfigParameter.WAZUH_MANAGER_KEY.name: "server-key.pem",
                ComponentCertsConfigParameter.WAZUH_MANAGER_CA.name: "server-ca.pem",
            },
            f"""
                sudo rm -rf {ComponentCertsDirectory.WAZUH_MANAGER}
                sudo mkdir -p {ComponentCertsDirectory.WAZUH_MANAGER}
                sudo tar -xf {CERTS_TOOL_PATH.parent}/wazuh-certificates.tar -C {ComponentCertsDirectory.WAZUH_MANAGER} ./server-cert.pem ./server-key.pem ./server-ca.pem
                sudo mv -n {ComponentCertsDirectory.WAZUH_MANAGER}/server-cert.pem {ComponentCertsDirectory.WAZUH_MANAGER}/server-cert.pem
                sudo mv -n {ComponentCertsDirectory.WAZUH_MANAGER}/server-key.pem {ComponentCertsDirectory.WAZUH_MANAGER}/server-key.pem
                sudo mv -n {ComponentCertsDirectory.WAZUH_MANAGER}/server-ca.pem {ComponentCertsDirectory.WAZUH_MANAGER}/server-ca.pem
                sudo chmod 500 {ComponentCertsDirectory.WAZUH_MANAGER}
                sudo find {ComponentCertsDirectory.WAZUH_MANAGER} -type f -exec chmod 400 {{}} \\;
                sudo chown -R root:root {ComponentCertsDirectory.WAZUH_MANAGER}/
            """,
        ),
        (
            Component.WAZUH_DASHBOARD,
            {
                ComponentCertsConfigParameter.WAZUH_DASHBOARD_CERT.name: "dashboard-cert.pem",
                ComponentCertsConfigParameter.WAZUH_DASHBOARD_KEY.name: "dashboard-key.pem",
                ComponentCertsConfigParameter.WAZUH_DASHBOARD_CA.name: "dashboard-ca.pem",
            },
            f"""
                sudo rm -rf {ComponentCertsDirectory.WAZUH_DASHBOARD}
                sudo mkdir -p {ComponentCertsDirectory.WAZUH_DASHBOARD}
                sudo tar -xf {CERTS_TOOL_PATH.parent}/wazuh-certificates.tar -C {ComponentCertsDirectory.WAZUH_DASHBOARD} ./dashboard-cert.pem ./dashboard-key.pem ./dashboard-ca.pem
                sudo mv -n {ComponentCertsDirectory.WAZUH_DASHBOARD}/dashboard-cert.pem {ComponentCertsDirectory.WAZUH_DASHBOARD}/dashboard-cert.pem
                sudo mv -n {ComponentCertsDirectory.WAZUH_DASHBOARD}/dashboard-key.pem {ComponentCertsDirectory.WAZUH_DASHBOARD}/dashboard-key.pem
                sudo mv -n {ComponentCertsDirectory.WAZUH_DASHBOARD}/dashboard-ca.pem {ComponentCertsDirectory.WAZUH_DASHBOARD}/dashboard-ca.pem
                sudo chmod 500 {ComponentCertsDirectory.WAZUH_DASHBOARD}
                sudo find {ComponentCertsDirectory.WAZUH_DASHBOARD} -type f -exec chmod 400 {{}} \\;
                sudo chown -R wazuh-dashboard:wazuh-dashboard {ComponentCertsDirectory.WAZUH_DASHBOARD}/
            """,
        ),
    ],
)
def test_copy_certs_to_component_directory_success(
    mock_exec_command, component, certs_name, expected_command, mock_logger
):
    certs_manager = CertsManager(raw_config_path=RAW_CONFIG_PATH, certs_tool_path=CERTS_TOOL_PATH)

    certs_manager.components_certs_default_name = {
        Component.WAZUH_INDEXER: {
            "cert": "indexer-cert.pem",
            "key": "indexer-key.pem",
            "ca": "indexer-ca.pem",
        },
        Component.WAZUH_MANAGER: {
            "cert": "server-cert.pem",
            "key": "server-key.pem",
            "ca": "server-ca.pem",
        },
        Component.WAZUH_DASHBOARD: {
            "cert": "dashboard-cert.pem",
            "key": "dashboard-key.pem",
            "ca": "dashboard-ca.pem",
        },
    }

    certs_manager.copy_certs_to_component_directory(
        component=component, certs_path=CERTS_TOOL_PATH.parent, certs_name=certs_name
    )

    mock_exec_command.assert_called()
    assert mock_exec_command.call_args.kwargs["command"].replace("\n", "").replace(" ", "") == expected_command.replace(
        "\n", ""
    ).replace(" ", "")
