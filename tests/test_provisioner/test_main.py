from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from pydantic import AnyUrl

from provisioner.main import (
    get_component_info,
    main,
    parse_componets,
)
from provisioner.models import ComponentInfo, Input
from utils import Component


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


@pytest.mark.parametrize(
    "packages_url_path, component, package_type, arch, dependencies, inventory",
    [
        (
            "/path/to/packages",
            Component.WAZUH_SERVER,
            "rpm",
            "x86_64",
            "/path/to/dependencies",
            "/path/to/inventory",
        ),
        (
            "/path/to/packages",
            Component.WAZUH_DASHBOARD,
            "deb",
            "arm64",
            "/path/to/dependencies",
            None,
        ),
        (
            "/path/to/packages",
            Component.ALL,
            "rpm",
            "x86_64",
            "/path/to/dependencies",
            "/path/to/inventory",
        ),
    ],
)
@patch("provisioner.main.Provisioner")
@patch("provisioner.main.parse_componets")
@patch("provisioner.main.Input")
def test_main(
    mock_input_class,
    mock_parse_componets,
    mock_provisioner_class,
    packages_url_path,
    component,
    package_type,
    arch,
    dependencies,
    inventory,
):
    mock_input_instance = Mock()
    mock_input_class.return_value = mock_input_instance

    mock_components = [Mock(), Mock()]
    mock_parse_componets.return_value = mock_components

    mock_provisioner_instance = Mock()
    mock_provisioner_class.return_value = mock_provisioner_instance

    main(
        packages_url_path=Path(packages_url_path),
        component=component,
        package_type=package_type,
        arch=arch,
        dependencies=Path(dependencies),
        inventory=Path(inventory) if inventory else None,
    )

    mock_input_class.assert_called_once_with(
        component=component,
        inventory_path=Path(inventory) if inventory else None,
        packages_url_path=Path(packages_url_path),
        package_type=package_type,
        arch=arch,
        dependencies_path=Path(dependencies),
    )

    mock_parse_componets.assert_called_once_with(mock_input_instance)

    mock_provisioner_class.assert_called_once_with(
        inventory=mock_input_instance.inventory_content,
        certs=mock_input_instance.certificates_content,
        password_tool=mock_input_instance.password_tool_content,
        components=mock_components,
        arch=mock_input_instance.arch,
        package_type=mock_input_instance.package_type,
    )

    mock_provisioner_instance.provision.assert_called_once()
