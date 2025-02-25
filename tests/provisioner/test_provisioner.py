from unittest.mock import patch

import pytest
from pydantic import AnyUrl

from provisioner import Provisioner
from provisioner.models.certs_info import CertsInfo
from provisioner.models.component_info import ComponentInfo
from provisioner.utils import Component, Package_manager, Package_type


@pytest.fixture()
def mock_exec_command():
    with patch("provisioner.provisioner.Provisioner.exec_command") as exec_command:
        exec_command.return_value = "", ""
        yield exec_command


@pytest.fixture()
def mock_logger():
    with patch("provisioner.provisioner.logger") as mock_logger_provisioner, patch(
        "provisioner.models.certs_info.logger"
    ) as mock_logger_certs, patch("generic.remote_connection.logger") as mock_logger_remote_connection:
        yield mock_logger_provisioner, mock_logger_certs, mock_logger_remote_connection


@pytest.fixture
def component_info_valid():
    dependencies = ["dependency1", "dependency2"]
    component_server = ComponentInfo(
        name=Component.WAZUH_SERVER,
        package_url=AnyUrl("http://packages-dev.wazuh.com"),
        dependencies=dependencies,
    )
    certs = CertsInfo(
        certs_url_content={
            "certs_tool": "http://packages-dev.wazuh.com/example/certs_tool",
            "config": "http://packages-dev.wazuh.com/example/certs_config",
        }
    )
    package_type = Package_type.RPM
    return Provisioner(
        inventory=None,
        certs=certs,
        components=[component_server],
        package_type=package_type,
    )


@pytest.fixture
def component_info_invalid_certs():
    dependencies = ["dependency1", "dependency2"]
    component_server = ComponentInfo(
        name=Component.WAZUH_SERVER,
        package_url=AnyUrl("http://packages-dev.wazuh.com"),
        dependencies=dependencies,
    )
    certs = CertsInfo(
        certs_url_content={
            "certs_tool": "http://example.com/certs_tool",
            "config": "http://example.com/certs_config",
        }
    )
    package_type = Package_type.RPM
    return Provisioner(
        inventory=None,
        certs=certs,
        components=[component_server],
        package_type=package_type,
    )


@pytest.mark.parametrize(
    "package_type, expected_result",
    [(Package_type.RPM, Package_manager.YUM), (Package_type.DEB, Package_manager.APT)],
)
def test_packege_manager_property_set_correct(package_type, expected_result, component_info_valid):
    component_info_valid.package_type = package_type

    assert component_info_valid.package_manager == expected_result


def test_provision_success(mock_logger, component_info_valid, mock_exec_command):
    component_info_valid.provision()

    assert mock_exec_command.call_count == 6  # 2 for dependencies, 2 for certs, 1 download package, 1 install package
    # dependencies
    assert mock_exec_command.call_args_list[0].kwargs == {
        "command": "mkdir -p ~/wazuh-ami-configure/certs && curl -s -o ~/wazuh-ami-configure/certs/certs_tool 'http://packages-dev.wazuh.com/example/certs_tool'",
        "client": None,
    }
    assert mock_exec_command.call_args_list[1].kwargs == {
        "command": "mkdir -p ~/wazuh-ami-configure/certs && curl -s -o ~/wazuh-ami-configure/certs/certs_config 'http://packages-dev.wazuh.com/example/certs_config'",
        "client": None,
    }

    # certs
    assert mock_exec_command.call_args_list[2].kwargs == {
        "command": "sudo dnf install -y dependency1",
        "client": None,
    }
    assert mock_exec_command.call_args_list[3].kwargs == {
        "command": "sudo dnf install -y dependency2",
        "client": None,
    }

    # package download and install
    assert mock_exec_command.call_args_list[4].kwargs == {
        "command": "mkdir -p ~/wazuh-ami-configure/packages && curl -s -o ~/wazuh-ami-configure/packages/wazuh_server.rpm 'http://packages-dev.wazuh.com/'",
        "client": None,
    }
    assert mock_exec_command.call_args_list[5].kwargs == {
        "command": "sudo dnf install -y ~/wazuh-ami-configure/packages/wazuh_server.rpm",
        "client": None,
    }
