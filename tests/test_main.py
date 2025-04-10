import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from main import DEPENDENCIES_FILE_PATH, main, parse_arguments


@pytest.fixture
def mock_execute_options():
    main_modules = [
        "provisioner_main",
        "core_configurer_main",
        "ami_configurer_main",
        "change_inventory_user",
    ]
    mocks = {module: MagicMock() for module in main_modules}

    with patch.multiple("main", **mocks):
        yield mocks


def test_parse_arguments_required():
    test_args = [
        "main.py",
        "--execute",
        "provisioner",
        "--inventory",
        "inventory.yaml",
        "--packages-url-path",
        "packages_url.yaml",
        "--execute",
        "all-ami",
    ]
    sys.argv = test_args
    args = parse_arguments()

    assert args.execute == "provisioner"
    assert args.inventory == "inventory.yaml"
    assert args.packages_url_path == "packages_url.yaml"
    assert args.package_type == "rpm"
    assert args.arch == "x86_64"
    assert args.dependencies == DEPENDENCIES_FILE_PATH
    assert args.component == "all"
    assert args.execute == "all-ami"


def test_parse_arguments_optional():
    test_args = [
        "main.py",
        "--execute",
        "provisioner",
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
    assert args.execute == "provisioner"
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
        (
            "ami-pre-configurer",
            '--inventory is required for the "ami-pre-configurer", "ami-post-configurer" and "all-ami" --execute value',
        ),
        ("core-configurer", ""),
        ("provisioner", '--packages-url-path is required for the "provisioner" and "all-ami" --execute value'),
        (
            "ami-post-configurer",
            '--inventory is required for the "ami-pre-configurer", "ami-post-configurer" and "all-ami" --execute value',
        ),
        ("all-ami", '--packages-url-path is required for the "provisioner" and "all-ami" --execute value'),
    ],
)
def test_main_without_required_args(module, error_message):
    test_args = ["main.py", "--execute", module]
    sys.argv = test_args

    if module != "core-configurer":
        with pytest.raises(ValueError, match=error_message):
            main()


def test_main_with_provisioner(mock_execute_options):
    test_args = [
        "main.py",
        "--packages-url-path",
        "packages_url.yaml",
        "--execute",
        "provisioner",
    ]
    sys.argv = test_args
    main()

    mock_execute_options["provisioner_main"].assert_called_once_with(
        packages_url_path=Path("packages_url.yaml"),
        package_type="rpm",
        arch="x86_64",
        dependencies=DEPENDENCIES_FILE_PATH,
        component="all",
        inventory=None,
    )
    mock_execute_options["core_configurer_main"].assert_not_called()
    mock_execute_options["ami_configurer_main"].assert_not_called()


def test_main_exeute_core_configurer(mock_execute_options):
    test_args = [
        "main.py",
        "--execute",
        "core-configurer",
    ]
    sys.argv = test_args
    main()

    mock_execute_options["core_configurer_main"].assert_called_once_with(inventory_path=None)
    mock_execute_options["provisioner_main"].assert_not_called()
    mock_execute_options["ami_configurer_main"].assert_not_called()


def test_main_execute_all_ami(mock_execute_options):
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

    mock_execute_options["ami_configurer_main"].return_value = "test_user"

    main()

    assert mock_execute_options["ami_configurer_main"].call_count == 2
    mock_execute_options["ami_configurer_main"].assert_any_call(
        inventory_path="inventory.yaml", type="ami-pre-configurer"
    )
    mock_execute_options["ami_configurer_main"].assert_any_call(
        inventory_path="inventory.yaml", type="ami-post-configurer"
    )
    mock_execute_options["provisioner_main"].assert_called_once()
    mock_execute_options["core_configurer_main"].assert_called_once()
    mock_execute_options["change_inventory_user"].assert_called_once_with(
        inventory_path="inventory.yaml", new_user="test_user"
    )


def test_mai_execute_ami_pre_configurer(mock_execute_options):
    test_args = [
        "main.py",
        "--inventory",
        "inventory.yaml",
        "--packages-url-path",
        "packages_url.yaml",
        "--execute",
        "ami-pre-configurer",
    ]
    sys.argv = test_args

    mock_execute_options["ami_configurer_main"].return_value = "test_user"

    main()

    mock_execute_options["ami_configurer_main"].assert_called_once_with(
        inventory_path="inventory.yaml", type="ami-pre-configurer"
    )
    mock_execute_options["change_inventory_user"].assert_called_once_with(
        inventory_path="inventory.yaml", new_user="test_user"
    )
    mock_execute_options["provisioner_main"].assert_not_called()
    mock_execute_options["core_configurer_main"].assert_not_called()


def test_ami_execute_ami_pre_configurer_no_user(mock_execute_options):
    test_args = [
        "main.py",
        "--inventory",
        "inventory.yaml",
        "--packages-url-path",
        "packages_url.yaml",
        "--execute",
        "ami-pre-configurer",
    ]
    sys.argv = test_args

    mock_execute_options["ami_configurer_main"].return_value = None

    with pytest.raises(ValueError, match="ami-pre-configurer did not return a new user"):
        main()


def test_ami_execute_ami_post_configurer(mock_execute_options):
    test_args = [
        "main.py",
        "--inventory",
        "inventory.yaml",
        "--packages-url-path",
        "packages_url.yaml",
        "--execute",
        "ami-post-configurer",
    ]
    sys.argv = test_args
    main()

    mock_execute_options["ami_configurer_main"].assert_called_once_with(
        inventory_path="inventory.yaml", type="ami-post-configurer"
    )
    mock_execute_options["provisioner_main"].assert_not_called()
    mock_execute_options["core_configurer_main"].assert_not_called()


@patch("main.ova_pre_configurer_main")
def test_main_execute_ova_pre_configurer(mock_ova_pre_configurer_main):
    test_args = [
        "main.py",
        "--execute",
        "ova-pre-configurer",
    ]
    sys.argv = test_args
    main()
    mock_ova_pre_configurer_main.assert_called_once()


@patch("main.core_configurer_main")
@patch("main.provisioner_main")
@patch("main.ova_post_configurer_main")
def test_main_execute_ova_post_configurer(
    mock_ova_post_configurer_main, mock_provisioner_main, mock_core_configurer_main
):
    test_args = [
        "main.py",
        "--packages-url-path",
        "packages_url.yaml",
        "--execute",
        "ova-post-configurer",
    ]
    sys.argv = test_args
    main()
    mock_ova_post_configurer_main.assert_called_once()
    mock_provisioner_main.assert_called_once()
    mock_core_configurer_main.assert_called_once()
