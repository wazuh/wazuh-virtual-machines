from unittest.mock import patch

import pytest

from configurer.ova.ova_pre_configurer.ova_pre_configurer import (
    VAGRANTFILE_PATH,
    add_vagrant_box,
    deploy_vm,
    main,
    run_vagrant_up,
)


@pytest.fixture
def mock_run_command():
    with patch(
        "configurer.ova.ova_pre_configurer.ova_pre_configurer.run_command"
    ) as mock_ova_pre_configurer_run_command:
        yield mock_ova_pre_configurer_run_command


@pytest.fixture
def mock_logger():
    with patch("configurer.ova.ova_pre_configurer.ova_pre_configurer.logger") as mock_logger:
        yield mock_logger


def test_add_vagrant_box_default_path(mock_logger, mock_run_command):
    add_vagrant_box()
    mock_logger.debug.assert_called_once_with("Adding Vagrant box.")
    mock_run_command.assert_called_once_with("vagrant box add --name al2023 al2023.box")


def test_add_vagrant_box_custom_path(mock_logger, mock_run_command):
    custom_path = "custom_path.box"
    add_vagrant_box(box_path=custom_path)
    mock_logger.debug.assert_called_once_with("Adding Vagrant box.")
    mock_run_command.assert_called_once_with(f"vagrant box add --name al2023 {custom_path}")


def test_run_vagrant_up_success(mock_logger, mock_run_command):
    mock_run_command.return_value = ("", "", [0])
    result = run_vagrant_up()
    assert result is True
    mock_logger.debug.assert_called_with("Attempt 1 to run 'vagrant up'.")
    mock_logger.info_success.assert_called_once_with("Vagrant VM started.")
    mock_run_command.assert_called_once_with("vagrant up", output=True)


def test_run_vagrant_up_failure_then_success(mock_run_command, mock_logger):
    def side_effect(command, output=True):
        if command == "vagrant up":
            if side_effect.counter == 0:
                side_effect.counter += 1
                return ("", "Error", [1])
            return ("", "", [0])
        elif command == "vagrant destroy -f":
            return ("", "", [0])
        return ("", "", [0])

    side_effect.counter = 0
    mock_run_command.side_effect = side_effect
    result = run_vagrant_up(max_retries=2)
    assert result is True
    assert mock_logger.debug.call_count == 3
    mock_logger.warning.assert_called_once_with("Vagrant VM failed to start on attemtp 1. Retrying...")
    mock_logger.info_success.assert_called_once_with("Vagrant VM started.")
    assert mock_run_command.call_count == 3
    mock_run_command.assert_any_call("vagrant up", output=True)
    mock_run_command.assert_any_call("vagrant destroy -f")


def test_run_vagrant_up_max_retries_exceeded(mock_logger, mock_run_command):
    mock_run_command.return_value = ("", "", [1])
    with pytest.raises(RuntimeError, match="Vagrant VM failed to start after maximum retries."):
        run_vagrant_up(max_retries=3)
    assert mock_logger.debug.call_count == 6
    assert mock_logger.warning.call_count == 3
    mock_logger.error.assert_called_once_with("Max attemps reached. Failed execution.")
    assert mock_run_command.call_count == 6
    mock_run_command.assert_any_call("vagrant up", output=True)
    mock_run_command.assert_any_call("vagrant destroy -f")


@patch("configurer.ova.ova_pre_configurer.ova_pre_configurer.run_vagrant_up")
@patch("configurer.ova.ova_pre_configurer.ova_pre_configurer.add_vagrant_box")
def test_deploy_vm_default_path(mock_add_vagrant_box, mock_run_vagrant_up, mock_logger, mock_run_command):
    deploy_vm()

    mock_logger.debug.assert_called_once_with("Deploying VM.")
    mock_run_command.assert_called_once_with(f"cp {VAGRANTFILE_PATH} .", check=True)
    mock_add_vagrant_box.assert_called_once()
    mock_run_vagrant_up.assert_called_once()


@patch("configurer.ova.ova_pre_configurer.ova_pre_configurer.run_vagrant_up")
@patch("configurer.ova.ova_pre_configurer.ova_pre_configurer.add_vagrant_box")
def test_deploy_vm_custom_path(mock_add_vagrant_box, mock_run_vagrant_up, mock_logger, mock_run_command):
    custom_path = "custom/Vagrantfile"
    deploy_vm(vagrantfile_path=custom_path)

    mock_logger.debug.assert_called_once_with("Deploying VM.")
    mock_run_command.assert_called_once_with(f"cp {custom_path} .", check=True)
    mock_add_vagrant_box.assert_called_once()
    mock_run_vagrant_up.assert_called_once()


@patch("configurer.ova.ova_pre_configurer.ova_pre_configurer.prepare_vm")
@patch("configurer.ova.ova_pre_configurer.ova_pre_configurer.deploy_vm")
@patch("configurer.ova.ova_pre_configurer.ova_pre_configurer.generate_base_box_main")
@patch("configurer.ova.ova_pre_configurer.ova_pre_configurer.install_dependencies_main")
def test_main(mock_install_dependencies, mock_generate_base_box, mock_deploy_vm, mock_prepare_vm, mock_logger):
    main()

    mock_logger.info.assert_any_call("--- Starting OVA PreConfigurer ---")
    mock_logger.info.assert_any_call("Installing dependencies.")
    mock_install_dependencies.assert_called_once()

    mock_logger.info.assert_any_call("Generating base box.")
    mock_generate_base_box.assert_called_once()

    mock_deploy_vm.assert_called_once()
    mock_prepare_vm.assert_called_once()
    mock_logger.info_success.assert_called_once_with("OVA PreConfigurer completed.")
