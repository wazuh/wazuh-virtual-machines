from unittest import mock
from unittest.mock import MagicMock, patch

import pytest
from pydantic import AnyUrl

from provisioner.models.certs_info import CertsInfo
from provisioner.models.component_info import ComponentInfo
from provisioner.models.password_tool_info import PasswordToolInfo
from provisioner.provisioner import Provisioner
from provisioner.utils import Package_manager, Package_type
from utils.enums import Component


@pytest.fixture()
def mock_exec_command():
    with patch("provisioner.provisioner.exec_command") as exec_command:
        exec_command.return_value = "", ""
        yield exec_command


@pytest.fixture
def component_info_valid(valid_inventory):
    dependencies = ["dependency1", "dependency2"]
    component_server = ComponentInfo(
        name=Component.WAZUH_SERVER,
        package_url=AnyUrl("http://packages-dev.wazuh.com"),
        dependencies=dependencies,
    )
    certs = CertsInfo(
        certs_url_content={
            "certs_tool": "http://packages-dev.wazuh.com/example/certs-tool.sh",
            "config": "http://packages-dev.wazuh.com/example/config.yml",
        }
    )
    password_tool = PasswordToolInfo(url=AnyUrl("http://packages-dev.wazuh.com/example/password-tool.sh"))

    package_type = Package_type.RPM
    return Provisioner(
        inventory=valid_inventory,
        certs=certs,
        password_tool=password_tool,
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


@patch("paramiko.SSHClient")
def test_provision_success(mock_paramiko, mock_logger, component_info_valid, mock_exec_command):
    mock_client_instance = MagicMock()
    mock_paramiko.return_value = mock_client_instance

    tools_expect_commands = [
        "mkdir -p ~/wazuh-configure/tools/certs && curl -s -o ~/wazuh-configure/tools/certs/certs-tool.sh 'http://packages-dev.wazuh.com/example/certs-tool.sh'",
        "mkdir -p ~/wazuh-configure/tools/certs && curl -s -o ~/wazuh-configure/tools/certs/config.yml 'http://packages-dev.wazuh.com/example/config.yml'",
        "mkdir -p ~/wazuh-configure/tools && curl -s -o ~/wazuh-configure/tools/password-tool.sh 'http://packages-dev.wazuh.com/example/password-tool.sh'",
    ]

    dependencies_expect_commands = [
        "sudo wget -q https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq",
        "sudo chmod +x /usr/bin/yq",
        "sudo dnf install -y dependency1",
        "sudo dnf install -y dependency2",
    ]

    package_expect_commands = [
        "mkdir -p ~/wazuh-configure/packages && curl -s -o ~/wazuh-configure/packages/wazuh_manager.rpm 'http://packages-dev.wazuh.com/'",
        "sudo dnf install -y ~/wazuh-configure/packages/wazuh_manager.rpm",
    ]

    component_info_valid.provision()

    mock_client_instance.connect.assert_called_once_with(
        hostname=component_info_valid.inventory.ansible_host,
        username=component_info_valid.inventory.ansible_user,
        port=component_info_valid.inventory.ansible_port,
        password=component_info_valid.inventory.ansible_password.get_secret_value()
        if component_info_valid.inventory.ansible_password
        else None,
        key_filename=str(component_info_valid.inventory.ansible_ssh_private_key_file),
    )

    assert (
        mock_exec_command.call_count == 8
    )  # 3 for dependencies, 3 for tools (certs-tool and password-tool), 1 download package, 1 install package

    # tools
    assert tools_expect_commands[0] in mock_exec_command.call_args_list[0].kwargs["command"]
    assert tools_expect_commands[1] in mock_exec_command.call_args_list[1].kwargs["command"]
    assert tools_expect_commands[2] in mock_exec_command.call_args_list[2].kwargs["command"]

    # dependencies
    assert dependencies_expect_commands[0] in mock_exec_command.call_args_list[3].kwargs["command"]
    assert dependencies_expect_commands[1] in mock_exec_command.call_args_list[3].kwargs["command"]
    assert dependencies_expect_commands[2] in mock_exec_command.call_args_list[4].kwargs["command"]
    assert dependencies_expect_commands[3] in mock_exec_command.call_args_list[5].kwargs["command"]

    # package
    assert package_expect_commands[0] in mock_exec_command.call_args_list[6].kwargs["command"]
    assert package_expect_commands[1] in mock_exec_command.call_args_list[7].kwargs["command"]
    mock_logger.debug_title.assert_any_call("Starting provisioning")
    mock_logger.debug_title.assert_any_call("Provisioning certificates files")
    mock_logger.debug_title.assert_any_call("Starting provisioning for wazuh manager")


@pytest.mark.parametrize(
    "certs_component, certs_method",
    [("certs-tool.sh", "certs_tool_provision"), ("config.yml", "certs_config_provision")],
)
@patch("paramiko.SSHClient")
def test_certs_tool_provision_success(
    mock_paramiko, certs_component, certs_method, mock_logger, component_info_valid, mock_exec_command
):
    mock_client_instance = MagicMock()
    mock_paramiko.return_value = mock_client_instance

    getattr(component_info_valid, certs_method)(mock_client_instance)

    mock_exec_command.assert_called_once_with(
        command=f"mkdir -p ~/wazuh-configure/tools/certs && curl -s -o ~/wazuh-configure/tools/certs/{certs_component} 'http://packages-dev.wazuh.com/example/{certs_component}'",
        client=mock_client_instance,
    )
    mock_logger.debug.assert_any_call(f"Provisioning {certs_component}")


@pytest.mark.parametrize(
    "certs_component, certs_method",
    [("certs-tool.sh", "certs_tool_provision"), ("config.yml", "certs_config_provision")],
)
@patch("paramiko.SSHClient")
def test_certs_tool_provision_failure(
    mock_paramiko, certs_component, certs_method, mock_logger, component_info_valid, mock_exec_command
):
    mock_client_instance = MagicMock()
    mock_paramiko.return_value = mock_client_instance
    mock_exec_command.return_value = "Bad output", "Error output"

    with pytest.raises(Exception, match=f"Error downloading {certs_component}"):
        getattr(component_info_valid, certs_method)(mock_client_instance)

    mock_exec_command.assert_called_once_with(
        command=f"mkdir -p ~/wazuh-configure/tools/certs && curl -s -o ~/wazuh-configure/tools/certs/{certs_component} 'http://packages-dev.wazuh.com/example/{certs_component}'",
        client=mock_client_instance,
    )
    mock_logger.debug.assert_any_call(f"Provisioning {certs_component}")
    mock_logger.error.assert_called_once_with(f"Error downloading {certs_component}: Error output")


@pytest.mark.parametrize(
    "dependencies, expected_commands",
    [
        (
            ["dependency1", "dependency2"],
            [
                "sudo dnf install -y dependency1",
                "sudo dnf install -y dependency2",
            ],
        ),
        (
            [],
            [],
        ),
    ],
)
@patch("paramiko.SSHClient")
def test_dependencies_provision(
    mock_paramiko, dependencies, expected_commands, mock_logger, component_info_valid, mock_exec_command
):
    mock_client_instance = MagicMock()
    mock_paramiko.return_value = mock_client_instance

    component_info_valid.components[0].dependencies = dependencies
    component_info_valid.dependencies_provision(component_info_valid.components[0], mock_client_instance)

    if dependencies:
        assert mock_exec_command.call_count == len(dependencies)
        for dependency in dependencies:
            mock_exec_command.assert_any_call(
                command=f"sudo dnf install -y {dependency}",
                client=mock_client_instance,
            )
        mock_logger.info_success.assert_any_call(
            f"Dependencies for {component_info_valid.components[0].name.replace('_', ' ')} installed successfully"
        )
    else:
        mock_exec_command.assert_not_called()
        mock_logger.info_success.assert_any_call(
            f"There are no dependencies to install for {component_info_valid.components[0].name.replace('_', ' ')}"
        )

    mock_logger.debug_title.assert_any_call(
        f"Provisioning dependencies for {component_info_valid.components[0].name.replace('_', ' ')}"
    )


@pytest.mark.parametrize(
    "package_manager, expected_command, expected_path",
    [
        (Package_manager.YUM, "sudo dnf install -y ", "~/wazuh-configure/packages/wazuh_manager.rpm"),
        (Package_manager.APT, "sudo dpkg -i ", "~/wazuh-configure/packages/wazuh_manager.deb"),
    ],
)
@patch("paramiko.SSHClient")
def test_packages_provision_success(
    mock_paramiko,
    package_manager,
    expected_command,
    expected_path,
    mock_logger,
    component_info_valid,
    mock_exec_command,
):
    mock_client_instance = MagicMock()
    mock_paramiko.return_value = mock_client_instance

    component_info_valid.package_type = Package_type.RPM if package_manager == Package_manager.YUM else Package_type.DEB

    component_info_valid.packages_provision(component_info_valid.components[0], mock_client_instance)

    mock_exec_command.assert_has_calls(
        [
            mock.call(
                command=f"mkdir -p ~/wazuh-configure/packages && curl -s -o {expected_path} 'http://packages-dev.wazuh.com/'",
                client=mock_client_instance,
            ),
            mock.call(
                command=f"{expected_command}{expected_path}",
                client=mock_client_instance,
            ),
        ],
    )

    mock_logger.debug_title.assert_any_call("Provisioning packages")
    mock_logger.debug.assert_any_call("Downloading wazuh manager package")


@pytest.mark.parametrize(
    "package_manager, component_name, package_url, expected_package_name",
    [
        (
            Package_manager.YUM,
            Component.WAZUH_SERVER,
            "http://packages-dev.wazuh.com/wazuh_manager.rpm",
            "wazuh_manager.rpm",
        ),
        (
            Package_manager.APT,
            Component.WAZUH_INDEXER,
            "http://packages-dev.wazuh.com/wazuh_indexer.deb",
            "wazuh_indexer.deb",
        ),
    ],
)
@patch("paramiko.SSHClient")
def test_get_package_by_url_success(
    mock_paramiko,
    package_manager,
    component_name,
    package_url,
    expected_package_name,
    mock_logger,
    component_info_valid,
    mock_exec_command,
):
    mock_client_instance = MagicMock()
    mock_paramiko.return_value = mock_client_instance

    component_info_valid.package_type = Package_type.RPM if package_manager == Package_manager.YUM else Package_type.DEB
    package_name = component_info_valid.get_package_by_url(component_name, AnyUrl(package_url), mock_client_instance)

    assert package_name == expected_package_name
    mock_exec_command.assert_called_once_with(
        command=f"mkdir -p ~/wazuh-configure/packages && curl -s -o ~/wazuh-configure/packages/{expected_package_name} '{package_url}'",
        client=mock_client_instance,
    )
    mock_logger.info_success.assert_called_once_with("Package downloaded successfully")


@pytest.mark.parametrize(
    "component_name, package_url, error_output",
    [
        (Component.WAZUH_SERVER, "http://packages-dev.wazuh.com/wazuh_manager.rpm", "Error output"),
        (Component.WAZUH_INDEXER, "http://packages-dev.wazuh.com/wazuh_indexer.deb", "Error output"),
    ],
)
@patch("paramiko.SSHClient")
def test_get_package_by_url_failure(
    mock_paramiko, component_name, package_url, error_output, mock_logger, component_info_valid, mock_exec_command
):
    mock_client_instance = MagicMock()
    mock_paramiko.return_value = mock_client_instance
    mock_exec_command.return_value = "", error_output

    with pytest.raises(RuntimeError, match="Error getting package"):
        component_info_valid.get_package_by_url(component_name, AnyUrl(package_url), mock_client_instance)

    mock_exec_command.assert_called_once_with(
        command=f"mkdir -p ~/wazuh-configure/packages && curl -s -o ~/wazuh-configure/packages/{component_name}.{component_info_valid.package_type} '{package_url}'",
        client=mock_client_instance,
    )
    mock_logger.error.assert_called_once_with(f"Error getting package: {error_output}")


@pytest.mark.parametrize(
    "output, error_output, expected_log, expected_exception",
    [
        ("", "", "installed successfully", None),
        ("is already installed", "", "is already installed", None),
        ("WARNING: something", "WARNING: something", "installed successfully", None),
        ("Bad output", "ERROR: something", "Error installing", RuntimeError),
    ],
)
@patch("paramiko.SSHClient")
def test_install_package(
    mock_paramiko,
    output,
    error_output,
    expected_log,
    expected_exception,
    mock_logger,
    component_info_valid,
    mock_exec_command,
):
    mock_client_instance = MagicMock()
    mock_paramiko.return_value = mock_client_instance
    mock_exec_command.return_value = output, error_output

    package_name = "test_package"
    command_template = "sudo dnf install -y {package_name}"

    if expected_exception:
        with pytest.raises(expected_exception, match=f"Error installing {package_name}"):
            component_info_valid.install_package(package_name, command_template, mock_client_instance)
    else:
        component_info_valid.install_package(package_name, command_template, mock_client_instance)

    mock_exec_command.assert_called_once_with(
        command=command_template.format(package_name=package_name),
        client=mock_client_instance,
    )

    if "installed successfully" in expected_log and "WARNING" not in error_output:
        mock_logger.info_success.assert_called_once_with(f"{package_name} {expected_log}")
    elif "is already installed" in expected_log:
        mock_logger.debug.assert_has_calls(
            [
                mock.call(f"Installing {package_name}"),
                mock.call(f"{package_name} {expected_log}"),
            ]
        )
    elif "installed successfully" in expected_log and "WARNING" in error_output:
        mock_logger.warning.assert_called_once_with(f"{error_output}")
        mock_logger.info_success.assert_called_once_with(f"{package_name} {expected_log}")
    else:
        mock_logger.error.assert_called_once_with(f"Error installing {package_name}: {error_output}")
