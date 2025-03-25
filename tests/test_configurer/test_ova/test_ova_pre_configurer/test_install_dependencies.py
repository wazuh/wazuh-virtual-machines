from unittest.mock import MagicMock, mock_open, patch

import pytest

from configurer.ova.ova_pre_configurer.install_dependencies import (
    REQUIRED_PACKAGES,
    VAGRANT_REPO_URL,
    download_virtualbox_installer,
    install_required_packages,
    install_vagrant,
    main,
    rebuild_virtualbox_kernel_modules,
    run_virtualbox_installer,
    update_packages,
)


@pytest.fixture
def mock_run_command():
    with patch("configurer.ova.ova_pre_configurer.install_dependencies.run_command") as mock_install_run_command:
        yield mock_install_run_command


@pytest.fixture
def mock_requests():
    with patch("configurer.ova.ova_pre_configurer.install_dependencies.requests") as mock_requests:
        yield mock_requests


@pytest.fixture
def mock_os_chmod():
    with patch("configurer.ova.ova_pre_configurer.install_dependencies.os.chmod") as mock_chmod:
        yield mock_chmod


@pytest.fixture
def mock_logger():
    with patch("configurer.ova.ova_pre_configurer.install_dependencies.logger") as mock_logger:
        yield mock_logger


def test_update_packages_success(mock_run_command):
    update_packages()
    mock_run_command.assert_called_once_with("sudo yum update -y")


def test_download_virtualbox_installer_success(mock_requests, mock_os_chmod, mock_logger):
    # Mock responses for requests
    mock_requests.get.side_effect = [
        MagicMock(status_code=200, text="7.1.6"),  # Response for LATEST-STABLE.TXT
        MagicMock(status_code=200, text="VirtualBox-7.1.6-12345-Linux_amd64.run"),  # Response for download page
        MagicMock(
            status_code=200, iter_content=lambda chunk_size: [b"file content"]
        ),  # Response for installer download
    ]

    # Mock file writing
    with patch("builtins.open", mock_open()) as mock_file:
        download_virtualbox_installer()

        # Assert requests were made correctly
        mock_requests.get.assert_any_call("https://download.virtualbox.org/virtualbox/LATEST-STABLE.TXT")
        mock_requests.get.assert_any_call("https://download.virtualbox.org/virtualbox/7.1.6/")
        mock_requests.get.assert_any_call(
            "https://download.virtualbox.org/virtualbox/7.1.6/VirtualBox-7.1.6-12345-Linux_amd64.run", stream=True
        )

        # Assert file was written
        mock_file.assert_called_once_with("/tmp/VirtualBox-7.1.6.run", "wb")
        mock_file().write.assert_called_with(b"file content")

        # Assert chmod was called
        mock_os_chmod.assert_called_once_with("/tmp/VirtualBox-7.1.6.run", 0o755)

        # Assert logger debug messages
        mock_logger.debug.assert_any_call("Latest VirtualBox version: 7.1.6")
        mock_logger.debug.assert_any_call("VirtualBox installer version 7.1.6 downloaded to /tmp/VirtualBox-7.1.6.run")
        mock_logger.debug.assert_any_call("Making installer executable.")


def test_download_virtualbox_installer_latest_version_failure(mock_requests, mock_logger):
    # Mock failure for LATEST-STABLE.TXT
    mock_requests.get.side_effect = [
        MagicMock(status_code=404, text="", raise_for_status=MagicMock(side_effect=Exception("Not Found")))
    ]

    with pytest.raises(RuntimeError, match="Error getting latest VirtualBox version."):
        download_virtualbox_installer()

    # Assert logger error message
    mock_logger.error.assert_called_once_with("Error getting latest VirtualBox version: Not Found")


def test_download_virtualbox_installer_download_page_failure(mock_requests, mock_logger):
    # Mock responses for LATEST-STABLE.TXT and failure for download page
    mock_requests.get.side_effect = [
        MagicMock(status_code=200, text="7.1.6"),  # Response for LATEST-STABLE.TXT
        MagicMock(status_code=404, raise_for_status=MagicMock(side_effect=Exception("Not Found"))),  # Download page
    ]

    with pytest.raises(Exception, match="Error getting VirtualBox download page."):
        download_virtualbox_installer()

    # Assert logger error message
    mock_logger.error.assert_called_once_with("Error getting VirtualBox download page: Not Found")


def test_download_virtualbox_installer_no_installer_url(mock_requests, mock_logger):
    # Mock responses for LATEST-STABLE.TXT and download page without matching installer URL
    mock_requests.get.side_effect = [
        MagicMock(status_code=200, text="7.1.6"),  # Response for LATEST-STABLE.TXT
        MagicMock(status_code=200, text="No matching installer"),  # Response for download page
    ]

    with pytest.raises(Exception, match="Could not find VirtualBox installer URL."):
        download_virtualbox_installer()

    # Assert logger error message
    mock_logger.error.assert_called_once_with("Could not find VirtualBox installer URL.")


def test_install_required_packages_success(mock_run_command, mock_logger):
    # Call the function

    install_required_packages()

    # Assert that the required packages were installed
    mock_run_command.assert_any_call("sudo yum install -y " + " ".join(REQUIRED_PACKAGES))

    # Assert that the development tools were installed
    mock_run_command.assert_any_call("sudo yum groupinstall 'Development Tools' -y")

    # Assert logger debug messages
    mock_logger.debug.assert_any_call(f"Installing required packages: {', '.join(REQUIRED_PACKAGES)}")
    mock_logger.debug.assert_any_call("Installing Development tools.")


def test_run_virtualbox_installer_success(mock_run_command, mock_logger):
    # Call the function
    run_virtualbox_installer()

    # Assert that the run_command was called with the correct command
    mock_run_command.assert_called_once_with("sudo bash /tmp/VirtualBox-*.run")

    # Assert logger debug message
    mock_logger.debug.assert_called_once_with("Running VirtualBox installer.")


def test_rebuild_virtualbox_kernel_modules_success(mock_run_command, mock_logger):
    # Call the function
    rebuild_virtualbox_kernel_modules()

    # Assert that the run_command was called with the correct command
    mock_run_command.assert_called_once_with("sudo /sbin/vboxconfig")

    # Assert logger debug message
    mock_logger.debug.assert_called_once_with("Rebuilding VirtualBox kernel modules.")


def test_install_vagrant_success(mock_run_command, mock_logger):
    # Call the function
    install_vagrant()

    # Assert that the run_command was called with the correct commands
    commands = [
        "sudo yum install -y yum-utils shadow-utils",
        f"sudo yum-config-manager --add-repo {VAGRANT_REPO_URL}",
        "sudo yum -y install vagrant",
    ]
    mock_run_command.assert_called_once_with(commands)

    # Assert logger debug message
    mock_logger.debug.assert_called_once_with("Installing Vagrant.")


@patch("configurer.ova.ova_pre_configurer.install_dependencies.install_vagrant")
@patch("configurer.ova.ova_pre_configurer.install_dependencies.rebuild_virtualbox_kernel_modules")
@patch("configurer.ova.ova_pre_configurer.install_dependencies.run_virtualbox_installer")
@patch("configurer.ova.ova_pre_configurer.install_dependencies.download_virtualbox_installer")
@patch("configurer.ova.ova_pre_configurer.install_dependencies.install_required_packages")
@patch("configurer.ova.ova_pre_configurer.install_dependencies.update_packages")
def test_main_success(
    mock_update_packages,
    mock_install_required_packages,
    mock_download_virtualbox_installer,
    mock_run_virtualbox_installer,
    mock_rebuild_virtualbox_kernel_modules,
    mock_install_vagrant,
    mock_run_command,
    mock_logger,
):
    # Call the main function
    main()

    # Assert that all the functions were called in the correct order
    mock_update_packages.assert_any_call()
    mock_install_required_packages.assert_called_once()
    mock_download_virtualbox_installer.assert_called_once()
    mock_run_virtualbox_installer.assert_called_once()
    assert mock_update_packages.call_count == 2  # Called twice
    mock_rebuild_virtualbox_kernel_modules.assert_called_once()
    mock_install_vagrant.assert_called_once()

    # Assert logger info messages
    mock_logger.info.assert_any_call("Installing dependencies of the OVA PreConfigurer.")
    mock_logger.info_success.assert_called_once_with("Dependencies installed successfully.")
