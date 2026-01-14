import pytest
from pydantic import AnyUrl

from provisioner.models.package_info import PackageInfo
from provisioner.utils import Component_arch, Package_type
from utils import Component


@pytest.fixture
def package_info():
    packages_url_content = {
        Component.WAZUH_INDEXER: {
            Package_type.RPM: {
                Component_arch.X86_64: "http://packages.wazuh.com/indexer/x86_64.rpm",
                Component_arch.AARCH64: "http://packages.wazuh.com/indexer/aarch64.rpm",
            }
        },
        Component.WAZUH_SERVER: {
            Package_type.RPM: {
                Component_arch.X86_64: "http://packages.wazuh.com/server/x86_64.rpm",
                Component_arch.AARCH64: "http://packages.wazuh.com/server/aarch64.rpm",
            }
        },
        Component.WAZUH_DASHBOARD: {
            Package_type.RPM: {
                Component_arch.X86_64: "http://packages.wazuh.com/dashboard/x86_64.rpm",
                Component_arch.AARCH64: "http://packages.wazuh.com/dashboard/aarch64.rpm",
            }
        },
    }
    return PackageInfo(packages_url_content=packages_url_content)


@pytest.mark.parametrize(
    "component, expected_output",
    [
        (
            "indexer",
            {
                Component_arch.X86_64: "http://packages.wazuh.com/indexer/x86_64.rpm",
                Component_arch.AARCH64: "http://packages.wazuh.com/indexer/aarch64.rpm",
            },
        ),
        (
            "server",
            {
                Component_arch.X86_64: "http://packages.wazuh.com/server/x86_64.rpm",
                Component_arch.AARCH64: "http://packages.wazuh.com/server/aarch64.rpm",
            },
        ),
        (
            "dashboard",
            {
                Component_arch.X86_64: "http://packages.wazuh.com/dashboard/x86_64.rpm",
                Component_arch.AARCH64: "http://packages.wazuh.com/dashboard/aarch64.rpm",
            },
        ),
    ],
)
def test_get_component_property_packages_success(component, expected_output, package_info):
    assert getattr(package_info, f"{component}_packages") == expected_output


@pytest.mark.parametrize(
    "component, attr_name",
    [
        (Component.WAZUH_INDEXER, "indexer_packages"),
        (Component.WAZUH_SERVER, "server_packages"),
        (Component.WAZUH_DASHBOARD, "dashboard_packages"),
    ],
)
def test_packages_missing_component(package_info, component, attr_name):
    package_info.packages_url_content.pop(component)

    with pytest.raises(KeyError, match=f"Packages for {component.value} not found."):
        _ = getattr(package_info, attr_name)


@pytest.mark.parametrize(
    "component, attr_name",
    [
        (Component.WAZUH_INDEXER, "indexer_packages"),
        (Component.WAZUH_SERVER, "server_packages"),
        (Component.WAZUH_DASHBOARD, "dashboard_packages"),
    ],
)
def test_packages_missing_package_type(package_info, component, attr_name):
    package_info.packages_url_content[component].pop(Package_type.RPM)

    with pytest.raises(KeyError, match=f"Packages for {component.value} with rpm type not found."):
        _ = getattr(package_info, attr_name)


@pytest.mark.parametrize(
    "component, package_type, expected_output",
    [
        (
            Component.WAZUH_INDEXER,
            Package_type.RPM,
            {
                Component_arch.X86_64: "http://packages.wazuh.com/indexer/x86_64.rpm",
                Component_arch.AARCH64: "http://packages.wazuh.com/indexer/aarch64.rpm",
            },
        ),
        (
            Component.WAZUH_SERVER,
            Package_type.RPM,
            {
                Component_arch.X86_64: "http://packages.wazuh.com/server/x86_64.rpm",
                Component_arch.AARCH64: "http://packages.wazuh.com/server/aarch64.rpm",
            },
        ),
        (
            Component.WAZUH_DASHBOARD,
            Package_type.RPM,
            {
                Component_arch.X86_64: "http://packages.wazuh.com/dashboard/x86_64.rpm",
                Component_arch.AARCH64: "http://packages.wazuh.com/dashboard/aarch64.rpm",
            },
        ),
    ],
)
def test_get_component_packages_success(package_info, component, package_type, expected_output):
    assert package_info.get_component_packages(component, package_type) == expected_output


@pytest.mark.parametrize(
    "component",
    [
        (Component.WAZUH_INDEXER),
        (Component.WAZUH_SERVER),
        (Component.WAZUH_DASHBOARD),
    ],
)
def test_get_component_packages_missing_component(package_info, component):
    package_info.packages_url_content.pop(component)

    with pytest.raises(KeyError, match=f"Packages for {component.value} not found."):
        package_info.get_component_packages(component)


@pytest.mark.parametrize(
    "component",
    [
        (Component.WAZUH_INDEXER),
        (Component.WAZUH_SERVER),
        (Component.WAZUH_DASHBOARD),
    ],
)
def test_get_component_packages_missing_package_type(package_info, component):
    package_info.packages_url_content[component].pop(Package_type.RPM)

    with pytest.raises(KeyError, match=f"Packages for {component.value} with rpm type not found."):
        package_info.get_component_packages(component, Package_type.RPM)


@pytest.mark.parametrize(
    "component, package_type, component_arch, expected_url",
    [
        (
            Component.WAZUH_INDEXER,
            Package_type.RPM,
            Component_arch.X86_64,
            AnyUrl("http://packages.wazuh.com/indexer/x86_64.rpm"),
        ),
        (
            Component.WAZUH_INDEXER,
            Package_type.RPM,
            Component_arch.AARCH64,
            AnyUrl("http://packages.wazuh.com/indexer/aarch64.rpm"),
        ),
        (
            Component.WAZUH_SERVER,
            Package_type.RPM,
            Component_arch.X86_64,
            AnyUrl("http://packages.wazuh.com/server/x86_64.rpm"),
        ),
        (
            Component.WAZUH_SERVER,
            Package_type.RPM,
            Component_arch.AARCH64,
            AnyUrl("http://packages.wazuh.com/server/aarch64.rpm"),
        ),
        (
            Component.WAZUH_DASHBOARD,
            Package_type.RPM,
            Component_arch.X86_64,
            AnyUrl("http://packages.wazuh.com/dashboard/x86_64.rpm"),
        ),
        (
            Component.WAZUH_DASHBOARD,
            Package_type.RPM,
            Component_arch.AARCH64,
            AnyUrl("http://packages.wazuh.com/dashboard/aarch64.rpm"),
        ),
    ],
)
def test_get_package_by_arch_success(package_info, component, package_type, component_arch, expected_url):
    assert package_info.get_package_by_arch(component, package_type, component_arch) == expected_url


@pytest.mark.parametrize(
    "component, package_type, component_arch",
    [
        (Component.WAZUH_INDEXER, Package_type.RPM, Component_arch.X86_64),
        (Component.WAZUH_SERVER, Package_type.RPM, Component_arch.X86_64),
        (Component.WAZUH_DASHBOARD, Package_type.RPM, Component_arch.X86_64),
    ],
)
def test_get_package_by_arch_invalid_url(package_info, component, package_type, component_arch):
    package_info.packages_url_content[component][package_type][component_arch] = "invalid_url"

    with pytest.raises(
        ValueError,
        match=f"URL for {component.value} with {component_arch.value} architecture has an invalid format.",
    ):
        package_info.get_package_by_arch(component, package_type, component_arch)


@pytest.mark.parametrize(
    "component, package_type, component_arch",
    [
        (Component.WAZUH_INDEXER, Package_type.RPM, Component_arch.X86_64),
        (Component.WAZUH_SERVER, Package_type.RPM, Component_arch.X86_64),
        (Component.WAZUH_DASHBOARD, Package_type.RPM, Component_arch.X86_64),
    ],
)
def test_get_package_by_arch_missing_arch(package_info, component, package_type, component_arch):
    package_info.packages_url_content[component][package_type].pop(component_arch)

    with pytest.raises(
        ValueError,
        match=f"Arch {component_arch.value} not found in {component.value} packages. Expected an URL but got None.",
    ):
        package_info.get_package_by_arch(component, package_type, component_arch)


@pytest.mark.parametrize(
    "component, package_type, component_arch",
    [
        (Component.WAZUH_INDEXER, Package_type.RPM, Component_arch.X86_64),
        (Component.WAZUH_SERVER, Package_type.RPM, Component_arch.X86_64),
        (Component.WAZUH_DASHBOARD, Package_type.RPM, Component_arch.X86_64),
    ],
)
def test_get_package_by_arch_invalid_host(package_info, component, package_type, component_arch):
    package_info.packages_url_content[component][package_type][component_arch] = "http://invalidhost.com/package.rpm"

    with pytest.raises(
        ValueError,
        match=f"URL for {component.value} with {component_arch.value} architecture is not for Wazuh packages.",
    ):
        package_info.get_package_by_arch(component, package_type, component_arch)
