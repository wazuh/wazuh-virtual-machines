from pathlib import Path

import yaml
from pydantic import AnyUrl

from provisioner.utils import (
    Component_arch,
    Package_type,
)
from utils import CertificatesComponent, Component, PasswordToolComponent


def file_to_dict(raw_urls_path: Path) -> dict:
    """
    Converts the contents of a YAML file into a dictionary.
    Args:
        raw_urls_path (Path): The path to the YAML file containing raw URLs.
    Raises:
        ValueError: If the file is empty or contains no valid content.
    Returns:
        dict: A dictionary representation of the YAML file content.
    """
    try:
        with open(raw_urls_path) as f:
            raw_url_content = yaml.safe_load(f) or {}
    except FileNotFoundError as err:
        raise FileNotFoundError(f"File not found in {raw_urls_path} path") from err

    if raw_url_content == {}:
        raise ValueError("No content found in raw URLs file")

    return raw_url_content


def get_component_packages(raw_urls_content: dict, component: Component) -> dict:
    """
    Extracts and organizes package information for a specified component from raw URL content.
    >>> raw_urls_content = {
    ...     "wazuh_indexer_url_amd64_deb": "https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/",
    ...     "wazuh_indexer_url_arm64_deb": "https://packages.wazuh.com/wazuh-indexer-example/arm64/deb/",
    ...     "wazuh_manager_url_amd64_deb": "https://packages.wazuh.com/wazuh-manager-example/amd64/deb/",
    ... }
    >>> component = Component.WAZUH_MANAGER
    >>> get_component_packages(raw_urls_content, component)
    {'wazuh_indexer': ['https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/', 'https://packages.wazuh.com/wazuh-indexer-example/arm64/deb/']}

    Args:
        raw_urls_content (dict): A dictionary containing raw URL content with component keys.
        component (Component): The component object for which packages need to be extracted.

    Returns:
        dict: A dictionary where the key is the component name (in lowercase) and the value is a list of packages associated with that component.
    """
    component_packages: dict = {}

    for component_key in raw_urls_content:
        if component.lower() in component_key:
            if component not in component_packages:
                component_packages[component.lower()] = []

            component_packages[component.lower()].append(raw_urls_content.get(component_key))

    return component_packages


def get_component_packages_by_arch(component_packages: list[str]) -> dict:
    """
    Given a list of component package URLs, this function returns a dictionary
    mapping each architecture type to its corresponding package URL.
    >>> component_packages = [
    ...     "https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/",
    ...     "https://packages.wazuh.com/wazuh-indexer-example/arm64/deb/",
    ... ]
    >>> get_component_packages_by_arch(component_packages)
    {'amd64': 'https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/',
    'arm64': 'https://packages.wazuh.com/wazuh-indexer-example/arm64/deb/'
    }

    Args:
        component_packages (List[str]): A list of URLs for component packages.

    Returns:
        dict: A dictionary where the keys are architecture types (as strings)
              and the values are the corresponding package URLs.
    """
    component_arch = {}

    for package_url in component_packages:
        for package_arch in Component_arch:
            if package_arch.lower() in package_url:
                component_arch[package_arch.lower()] = package_url

    return component_arch


def get_component_packages_by_type(component_packages: dict) -> dict:
    """
    Organizes component packages by their type.

    This function takes a dictionary of component packages, where the keys are package architectures
    and the values are package URLs. It categorizes these packages based on their type, which is
    determined by the presence of the type name in the package URL.
    >>> component_packages = {
    ...     "amd64": "https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/",
    ...     "arm64": "https://packages.wazuh.com/wazuh-indexer-example/arm64/deb/",
    ...     "x86_64": "https://packages.wazuh.com/wazuh-indexer-example/x86_64/rpm/",
    ... }
    >>> get_component_packages_by_type(component_packages)
    {'deb': {'amd64': 'https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/',
            'arm64': 'https://packages.wazuh.com/wazuh-indexer-example/arm64/deb/'},
     'rpm': {'x86_64': 'https://packages.wazuh.com/wazuh-indexer-example/x86_64/rpm/'}
    }
    Args:
        component_packages (dict): A dictionary where keys are package architectures (e.g., 'x86_64')
                                   and values are package URLs (e.g., 'http://example.com/package_x86_64.deb').

    Returns:
        dict: A dictionary where keys are package types (e.g., 'deb', 'rpm') and values are dictionaries
              mapping package architectures to package URLs.
    """
    component_type = {package_type.lower(): {} for package_type in Package_type}

    for package_arch, package_url in component_packages.items():
        for component_type_key in component_type:
            if component_type_key in package_url:
                component_type.get(component_type_key, {}).update({package_arch: package_url})

    return component_type


def format_certificates_urls_file(raw_urls_path: Path) -> dict:
    """
    Formats a file containing raw URLs into a dictionary of certificate URLs.

    This function reads a file containing raw URLs and maps them to a dictionary
    where the keys are the lowercase names of certificate components and the values
    are the corresponding URLs.
    >>> raw_urls_path = Path("certificates_urls.yaml")
    >>> format_certificates_urls_file(raw_urls_path)
    {'certs_tool': 'https://packages.wazuh.com/certificates-example/certs_tool',
    'config': 'https://packages.wazuh.com/certificates-example/certs_config'
    }

    Args:
        raw_urls_path (Path): The path to the file containing the raw URLs.

    Returns:
        dict: A dictionary where the keys are the lowercase names of certificate
              components and the values are the corresponding URLs.
    """
    certificates_urls = {certs_component.name.lower(): "" for certs_component in CertificatesComponent}
    raw_urls_content = file_to_dict(raw_urls_path)

    for component_name, url in raw_urls_content.items():
        for certs_component in CertificatesComponent:
            if certs_component.name.lower() in component_name:
                certificates_urls[certs_component.name.lower()] = url
    return certificates_urls


def format_password_tool_urls_file(raw_urls_path: Path) -> AnyUrl | None:
    """
    Formats a file containing raw URLs into a string of password tool URL.

    This function reads a file containing raw URLs and retrieves the URL
    for the password tool.

    >>> raw_urls_path = Path("password_tool_urls.yaml")
    >>> format_password_tool_urls_file(raw_urls_path)
    'https://packages.wazuh.com/password-tool-example/password_tool'

    Args:
        raw_urls_path (Path): The path to the file containing the raw URLs.

    Returns:
        str: The URL for the password tool.
    """
    raw_urls_content = file_to_dict(raw_urls_path)

    for component_name, url in raw_urls_content.items():
        if PasswordToolComponent.PASSWORD_TOOL.name.lower() in component_name.lower():
            return AnyUrl(url)
    return None


def format_component_urls_file(raw_urls_path: Path) -> dict:
    """
    Formats the component URLs file by processing raw URLs and organizing them by component, architecture, and type.

    Args:
        raw_urls_path (Path): The path to the raw URLs file.
    >>> raw_urls_path = Path("component_urls.yaml")
    ... raw_urls_content = {
    ...     "wazuh_indexer_url_amd64_deb": "https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/",
    ...     "wazuh_indexer_url_arm64_deb": "https://packages.wazuh.com/wazuh-indexer-example/arm64/deb/",
    ...     "wazuh_manager_url_x86_64_rpm": "https://packages.wazuh.com/wazuh-manager-example/x86_64/rpm/",
    ... }
    ... format_component_urls_file(raw_urls_path)
    {'wazuh_indexer': {'deb': {'amd64': 'https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/',
                               'arm64': 'https://packages.wazuh.com/wazuh-indexer-example/arm64/deb/'},
                       'rpm': {}
                    },
    'wazuh_manager': {'deb': {},
                     'rpm': {'x86_64': 'https://packages.wazuh.com/wazuh-manager-example/x86_64/rpm/'}
                    }
    }

    Returns:
        dict: A dictionary where the keys are component names (in lowercase) and the values are dictionaries containing
              the organized URLs by architecture and type.
    """
    urls_file_content = {component.lower(): {} for component in Component if component.lower() != "all"}
    raw_urls_content = file_to_dict(raw_urls_path)

    for component in Component:
        if component.lower() != "all":
            component_packages = get_component_packages(raw_urls_content, component)
            component_arch = get_component_packages_by_arch(component_packages.get(component.lower(), {}))
            component_type = get_component_packages_by_type(component_arch)
            urls_file_content.get(component.lower(), {}).update(component_type)

    return urls_file_content
