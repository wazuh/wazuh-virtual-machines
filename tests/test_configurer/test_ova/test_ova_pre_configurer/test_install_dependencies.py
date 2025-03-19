from unittest.mock import patch

import pytest

from configurer.ova.ova_pre_configurer.install_dependencies import update_packages


@pytest.fixture
def mock_run_command():
    with patch("configurer.ova.ova_pre_configurer.install_dependencies.run_command") as mock_install_run_command:
        yield mock_install_run_command


def test_update_packages_success(mock_run_command):
    update_packages()
    mock_run_command.assert_called_once_with("sudo yum update -y")
