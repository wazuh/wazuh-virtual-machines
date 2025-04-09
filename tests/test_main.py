import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from main import DEPENDENCIES_FILE_PATH, main, parse_arguments
from provisioner.models import Input


def test_parse_arguments_required():
    test_args = [
        "main.py",
        "--packages-url-path",
        "packages_url.yaml",
        "--execute",
        "all-ami",
    ]
    sys.argv = test_args
    args = parse_arguments()

    assert args.inventory is None
    assert args.packages_url_path == "packages_url.yaml"
    assert args.package_type == "rpm"
    assert args.arch == "x86_64"
    assert args.dependencies == DEPENDENCIES_FILE_PATH
    assert args.component == "all"
    assert args.execute == "all-ami"


def test_parse_arguments_optional():
    test_args = [
        "main.py",
        "--inventory",
        "inventory.yaml",
        "--packages-url-path",
        "packages_url.yaml",
        "--package-type",
        "deb",
        "--execute",
        "all-ami",
        "--arch",
        "arm64",
        "--dependencies",
        "custom_dependencies.yaml",
        "--component",
        "wazuh_server",
    ]
    sys.argv = test_args
    args = parse_arguments()
    assert args.inventory == "inventory.yaml"
    assert args.packages_url_path == "packages_url.yaml"
    assert args.package_type == "deb"
    assert args.execute == "all-ami"
    assert args.arch == "arm64"
    assert args.dependencies == "custom_dependencies.yaml"
    assert args.component == "wazuh_server"


@pytest.mark.parametrize(
    "arg_name, arg_value",
    [
        ("--package-type", "invalid"),
        ("--arch", "invalid"),
        ("--component", "invalid"),
        ("--execute", "invalid"),
    ],
)
def test_parse_arguments_invalid_values(arg_name, arg_value):
    test_args = [
        "main.py",
        "--inventory",
        "inventory.yaml",
        "--packages-url-path",
        "packages_url.yaml",
        arg_name,
        arg_value,
    ]
    sys.argv = test_args
    with pytest.raises(SystemExit):
        parse_arguments()


@pytest.mark.parametrize(
    "module, error_message",
    [
        ("ami-configurer", '--inventory is required for the "ami-configurer" and "all-ami" --execute value'),
        ("core-configurer", ""),
        (
            "provisioner",
            '--packages-url-path is required for the "provisioner", "all-ami" and "ova-post-configurer" --execute value',
        ),
        (
            "all-ami",
            '--packages-url-path is required for the "provisioner", "all-ami" and "ova-post-configurer" --execute value',
        ),
    ],
)
def test_main_without_required_args(module, error_message):
    test_args = ["main.py", "--execute", module]
    sys.argv = test_args

    if module != "core-configurer":
        with pytest.raises(ValueError, match=error_message):
            main()


@patch("main.core_configurer_main")
@patch("main.provisioner_main")
def test_main_execute_provisioner(mock_provisioner_main, mock_configurer_main):
    test_args = [
        "main.py",
        "--packages-url-path",
        "packages_url.yaml",
        "--execute",
        "provisioner",
    ]
    sys.argv = test_args
    main()
    mock_provisioner_main.assert_called_once()
    mock_configurer_main.assert_not_called()


@patch("main.core_configurer_main")
@patch("main.provisioner_main")
def test_main_execute_configurer(mock_provisioner_main, mock_configurer_main):
    test_args = [
        "main.py",
        "--execute",
        "core-configurer",
    ]
    sys.argv = test_args
    main()
    mock_configurer_main.assert_called_once()
    mock_provisioner_main.assert_not_called()


@patch("main.core_configurer_main")
@patch("main.provisioner_main")
@patch("main.ami_configurer_main")
@patch("main.change_inventory_user")
def test_main_execute_all(
    mock_change_inventory_user, mock_ami_configurer_main, mock_provisioner_main, mock_configurer_main
):
    test_args = [
        "main.py",
        "--inventory",
        "inventory.yaml",
        "--packages-url-path",
        "packages_url.yaml",
        "--execute",
        "all-ami",
    ]
    sys.argv = test_args
    main()
    mock_ami_configurer_main.assert_called_once()
    mock_provisioner_main.assert_called_once()
    mock_configurer_main.assert_called_once()
    mock_change_inventory_user.assert_called_once()
