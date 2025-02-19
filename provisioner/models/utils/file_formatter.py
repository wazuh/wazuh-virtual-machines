from pathlib import Path
from typing import List
import yaml
from provisioner.utils import Component, Package_type, Component_arch, CertificatesComponent

def file_to_dict(raw_urls_path: Path) -> dict:
    with open(raw_urls_path, "r") as f:
        raw_url_content = yaml.safe_load(f) or None

    if raw_url_content is None:
        raise ValueError("No content found in raw URLs file")
    
    return raw_url_content

def get_component_packages(raw_urls_content: dict, component: Component) -> dict:
    component_packages: dict = {}
    
    for component_key in raw_urls_content.keys():

        if component.name.lower() in component_key:
            if component not in component_packages:
                component_packages[component.name.lower()] = []

            component_packages[component.name.lower()].append(raw_urls_content.get(component_key))

    return component_packages

def get_component_packages_by_arch(component_packages: List[str]) -> dict:
    component_arch = {}
    
    for package_url in component_packages:
        for package_arch in Component_arch:
            if package_arch.name.lower() in package_url:
                component_arch[package_arch.name.lower()] = package_url
                    
    return component_arch

def get_component_packages_by_type(component_packages: dict) -> dict:
    component_type = {package_type.name.lower(): {} for package_type in Package_type}
    
    for package_arch, package_url in component_packages.items():
        for component_type_key in component_type.keys():
            if component_type_key in package_url:
                component_type.get(component_type_key, {}).update({package_arch: package_url})
    
    return component_type

def format_certificates_urls_file(raw_urls_path: Path) -> dict:
    certificates_urls = {certs_component.name.lower(): "" for certs_component in CertificatesComponent}
    raw_urls_content = file_to_dict(raw_urls_path)

    for component_name, url in raw_urls_content.items():
        for certs_component in CertificatesComponent:
            if certs_component.name.lower() in component_name:
                certificates_urls[certs_component.name.lower()] = url
    return certificates_urls

def format_component_urls_file(raw_urls_path: Path) -> dict:
    urls_file_content = {component.name.lower(): {} for component in Component if component.name.lower() != "all"}
    raw_urls_content = file_to_dict(raw_urls_path)

    for component in Component:
        if component.name.lower() != "all":
            component_packages = get_component_packages(raw_urls_content, component)
            component_arch = get_component_packages_by_arch(component_packages.get(component.name.lower(), {}))
            component_type = get_component_packages_by_type(component_arch)
            urls_file_content.get(component.name.lower(), {}).update(component_type)
    
    return urls_file_content
