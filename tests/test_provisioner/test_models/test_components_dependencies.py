import pytest

from provisioner.models.components_dependencies import ComponentsDependencies
from provisioner.utils import Package_manager, Package_type
from utils import Component


def test_get_component_dependencies_success():
    dependencies_content = {
        Component.WAZUH_INDEXER: {
            Package_manager.YUM: ["dep1", "dep2"],
            Package_manager.APT: ["dep3", "dep4"],
        },
        Component.WAZUH_MANAGER: {
            Package_manager.YUM: ["dep5", "dep6"],
            Package_manager.APT: ["dep7", "dep8"],
        },
        Component.WAZUH_DASHBOARD: {
            Package_manager.YUM: ["dep9", "dep10"],
            Package_manager.APT: ["dep11", "dep12"],
        },
    }
    components_dependencies = ComponentsDependencies(
        dependencies_content=dependencies_content, package_type=Package_type.RPM
    )

    assert components_dependencies.indexer_dependencies == ["dep1", "dep2"]
    assert components_dependencies.server_dependencies == ["dep5", "dep6"]
    assert components_dependencies.dashboard_dependencies == ["dep9", "dep10"]


def test_get_component_dependencies_key_error():
    dependencies_content = {Component.WAZUH_INDEXER: {Package_manager.YUM: ["dep1", "dep2"]}}
    components_dependencies = ComponentsDependencies(
        dependencies_content=dependencies_content, package_type=Package_type.RPM
    )

    with pytest.raises(KeyError, match="Dependencies for wazuh_manager not found"):
        components_dependencies.get_component_dependencies(Component.WAZUH_MANAGER)


def test_get_component_dependencies_empty_list():
    dependencies_content = {Component.WAZUH_INDEXER: {Package_manager.YUM: []}}
    components_dependencies = ComponentsDependencies(
        dependencies_content=dependencies_content, package_type=Package_type.RPM
    )

    assert components_dependencies.get_component_dependencies(Component.WAZUH_INDEXER) == []


def test_package_manager_rpm():
    dependencies_content = {}
    components_dependencies = ComponentsDependencies(
        dependencies_content=dependencies_content, package_type=Package_type.RPM
    )

    assert components_dependencies.package_manager == Package_manager.YUM


def test_package_manager_apt():
    dependencies_content = {}
    components_dependencies = ComponentsDependencies(
        dependencies_content=dependencies_content, package_type=Package_type.DEB
    )

    assert components_dependencies.package_manager == Package_manager.APT
