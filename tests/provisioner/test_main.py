import sys
from unittest.mock import Mock, patch

import pytest
from pydantic import AnyUrl

from provisioner.main import (
    DEPENDENCIES_FILE_PATH,
    get_component_info,
    main,
    parse_arguments,
    parse_componets,
)
from provisioner.models import ComponentInfo, Input
from utils import Component


def test_parse_arguments_required():
    test_args = [
        "main.py",
        "--inventory",
        "inventory.yaml",
        "--packages-url-path",
        "packages_url.yaml",
    ]
    sys.argv = test_args
    args = parse_arguments()
    assert args.inventory == "inventory.yaml"
    assert args.packages_url_path == "packages_url.yaml"
    assert args.package_type == "rpm"
    assert args.arch == "x86_64"
    assert args.dependencies == DEPENDENCIES_FILE_PATH
    assert args.component == "all"


def test_parse_arguments_optional():
    test_args = [
        "main.py",
        "--inventory",
        "inventory.yaml",
        "--packages-url-path",
        "packages_url.yaml",
        "--package-type",
        "deb",
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
    assert args.arch == "arm64"
    assert args.dependencies == "custom_dependencies.yaml"
    assert args.component == "wazuh_server"


@pytest.mark.parametrize(
    "arg_name, arg_value",
    [
        ("--package-type", "invalid"),
        ("--arch", "invalid"),
        ("--component", "invalid"),
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
    "package_type, arch, package_url, dependencies, component",
    [
        (
            "rpm",
            "x86_64",
            "http://example.com/package.rpm",
            ["dependency1", "dependency2"],
            Component.WAZUH_SERVER,
        ),
        ("deb", "arm64", "http://example.com/package.deb", [], Component.WAZUH_DASHBOARD),
    ],
)
def test_get_component_info(package_type, arch, package_url, dependencies, component):
    mock_input = Mock(spec=Input)
    mock_input.package_type = package_type
    mock_input.arch = arch
    mock_input.packages_url_content.get_package_by_arch.return_value = package_url
    mock_input.dependencies.get_component_dependencies.return_value = dependencies

    result = get_component_info(mock_input, component)

    assert isinstance(result, ComponentInfo)
    assert result.name == component
    assert result.package_url == AnyUrl(package_url)
    assert result.dependencies == dependencies
    mock_input.packages_url_content.get_package_by_arch.assert_called_once_with(
        component=component, package_type=package_type, component_arch=arch
    )
    mock_input.dependencies.get_component_dependencies.assert_called_once_with(component=component)


@pytest.mark.parametrize(
    "component, expected_components, package_type, arch",
    [
        (
            Component.ALL,
            [
                ComponentInfo(
                    name=Component.WAZUH_INDEXER,
                    package_url=AnyUrl("http://example.com/all.rpm"),
                    dependencies=["dependency1", "dependency2"],
                ),
                ComponentInfo(
                    name=Component.WAZUH_SERVER,
                    package_url=AnyUrl("http://example.com/all.rpm"),
                    dependencies=["dependency1", "dependency2"],
                ),
                ComponentInfo(
                    name=Component.WAZUH_DASHBOARD,
                    package_url=AnyUrl("http://example.com/all.rpm"),
                    dependencies=["dependency1", "dependency2"],
                ),
            ],
            "rpm",
            "x86_64",
        ),
        (
            Component.WAZUH_INDEXER,
            [
                ComponentInfo(
                    name=Component.WAZUH_INDEXER,
                    package_url=AnyUrl("http://example.com/indexer.rpm"),
                    dependencies=["dependency1", "dependency2"],
                )
            ],
            "rpm",
            "x86_64",
        ),
        (
            Component.WAZUH_SERVER,
            [
                ComponentInfo(
                    name=Component.WAZUH_SERVER,
                    package_url=AnyUrl("http://example.com/server.rpm"),
                    dependencies=["dependency3", "dependency4"],
                )
            ],
            "rpm",
            "x86_64",
        ),
        (
            Component.WAZUH_DASHBOARD,
            [
                ComponentInfo(
                    name=Component.WAZUH_DASHBOARD,
                    package_url=AnyUrl("http://example.com/dashboard.deb"),
                    dependencies=["dependency5", "dependency6"],
                )
            ],
            "deb",
            "arm64",
        ),
    ],
)
def test_parse_componets(component, expected_components, package_type, arch):
    mock_input = Mock(spec=Input)
    mock_input.component = component
    mock_input.package_type = package_type
    mock_input.arch = arch
    mock_input.packages_url_content.get_package_by_arch.return_value = expected_components[0].package_url
    mock_input.dependencies.get_component_dependencies.return_value = expected_components[0].dependencies

    result = parse_componets(mock_input)

    for res in result:
        assert isinstance(res, ComponentInfo)
        assert next(
            res
            for arg in mock_input.packages_url_content.get_package_by_arch.call_args_list
            if arg.kwargs["component"] == res.name
            and arg.kwargs["package_type"] == package_type
            and arg.kwargs["component_arch"] == arch
        )
        assert next(
            res
            for arg in mock_input.dependencies.get_component_dependencies.call_args_list
            if arg.kwargs["component"] == res.name
        )
    assert result == expected_components
    assert isinstance(result, list)


@patch("provisioner.main.parse_arguments")
@patch("provisioner.main.Input")
@patch("provisioner.main.parse_componets")
@patch("provisioner.main.Provisioner")
def test_main(mock_provisioner, mock_parse_componets, mock_input, mock_parse_arguments):
    mock_args = Mock()
    mock_args.component = "wazuh_server"
    mock_args.inventory = "inventory.yaml"
    mock_args.packages_url_path = AnyUrl("http://example.com/server.rpm")
    mock_args.package_type = "rpm"
    mock_args.arch = "x86_64"
    mock_args.dependencies = "dependencies.yaml"
    mock_parse_arguments.return_value = mock_args

    # Mock the Input object
    mock_input_instance = Mock(spec=Input)
    mock_input_instance.component = mock_args.component
    mock_input_instance.arch = mock_args.arch
    mock_input_instance.package_type = mock_args.package_type
    mock_input.return_value = mock_input_instance

    # Mock the parsed components
    mock_components = [Mock()]
    mock_parse_componets.return_value = mock_components

    main()

    mock_parse_arguments.assert_called_once()
    mock_input.assert_called_once_with(
        component=mock_args.component,
        inventory_path=mock_args.inventory,
        packages_url_path=mock_args.packages_url_path,
        package_type=mock_args.package_type,
        arch=mock_args.arch,
        dependencies_path=mock_args.dependencies,
    )
    mock_parse_componets.assert_called_once_with(mock_input_instance)
    mock_provisioner.assert_called_once_with(
        inventory=mock_input_instance.inventory_content,
        certs=mock_input_instance.certificates_content,
        components=mock_components,
        arch=mock_input_instance.arch,
        package_type=mock_input_instance.package_type,
    )
    mock_provisioner.return_value.provision.assert_called_once()
