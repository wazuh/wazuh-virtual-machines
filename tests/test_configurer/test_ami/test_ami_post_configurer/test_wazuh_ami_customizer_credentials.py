import importlib.util
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

CUSTOMIZER_PATH = (
    Path(__file__).resolve().parents[4] / "configurer" / "ami" / "ami_post_configurer" / "wazuh-ami-customizer.py"
)


@pytest.fixture(scope="module")
def customizer():
    """Loads wazuh-ami-customizer.py as a module (its file name has a hyphen, and it opens /var/log at import)."""

    spec = importlib.util.spec_from_file_location("wazuh_ami_customizer_credentials", CUSTOMIZER_PATH)
    module = importlib.util.module_from_spec(spec)
    with patch("logging.FileHandler", return_value=logging.NullHandler()):
        spec.loader.exec_module(module)
    return module


def fake_metadata(command: str) -> str:
    if command == "hostname -s":
        return "wazuh\n"
    if command == "hostname -I":
        return "172.31.5.10 2600:1f18:aa::5\n"
    if "--public-ipv4" in command:
        return " 203.0.113.9\n"
    if "--local-hostname" in command:
        return " ip-172-31-5-10.ec2.internal\n"
    if "--public-hostname" in command:
        return " not available\n"
    return ""


def test_get_manager_sans_names_the_instance_with_prefixes(customizer, monkeypatch):
    commands = []

    def run(command, error_message):
        commands.append(command)
        return fake_metadata(command)

    monkeypatch.setattr(customizer, "run_command", run)

    # Prefixed (RC 2), the ENI's IPv6 from hostname -I, DNS names so agents can enroll by name
    # (TC-03), and a metadata "not available" left out.
    assert customizer.get_manager_sans() == [
        "DNS:wazuh",
        "IP:172.31.5.10",
        "IP:2600:1f18:aa::5",
        "IP:203.0.113.9",
        "DNS:ip-172-31-5-10.ec2.internal",
    ]
    # The AL2023 ec2-metadata has no --ipv6 option.
    assert not any("--ipv6" in command for command in commands)


def test_install_credentials_writes_the_manager_sans_then_installs_in_order(customizer, monkeypatch):
    monkeypatch.setattr(customizer, "get_manager_sans", lambda: ["IP:172.31.5.10", "IP:203.0.113.9"])
    run = MagicMock(return_value="")
    monkeypatch.setattr(customizer, "run_command", run)

    customizer.install_credentials()

    commands = [call.kwargs["command"] for call in run.call_args_list]
    local_env = commands[0]
    assert "install -m 0600 -o root -g root /dev/null /etc/wazuh-manager/local.env" in local_env
    assert "'WAZUH_MANAGER_REMOTED_CERT_SANS=IP:172.31.5.10,IP:203.0.113.9'" in local_env
    assert "'WAZUH_MANAGER_APID_CERT_SANS=IP:172.31.5.10,IP:203.0.113.9'" in local_env
    # The indexer first: the manager and the dashboard import its export/, the dashboard the manager's too.
    assert commands[1:4] == [
        "/usr/share/wazuh-indexer/bin/resolve-credentials.sh --install < /dev/null",
        "/var/wazuh-manager/bin/wazuh-manager-resolve-credentials --install < /dev/null",
        "/usr/share/wazuh-dashboard/bin/resolve-credentials --install < /dev/null",
    ]
    assert commands[4] == "/var/wazuh-manager/bin/wazuh-manager-certs stamp"
