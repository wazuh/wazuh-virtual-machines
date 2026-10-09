import importlib.util
import json
import logging
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

CUSTOMIZER_PATH = (
    Path(__file__).resolve().parents[4] / "configurer" / "ami" / "ami_post_configurer" / "wazuh-ami-customizer.py"
)


@pytest.fixture(scope="module")
def customizer():
    """Loads wazuh-ami-customizer.py as a module (see test_wazuh_ami_customizer_certs_tar.py)."""

    spec = importlib.util.spec_from_file_location("wazuh_ami_customizer_agent_reset", CUSTOMIZER_PATH)
    module = importlib.util.module_from_spec(spec)
    with patch("logging.FileHandler", return_value=logging.NullHandler()):
        spec.loader.exec_module(module)
    return module


@pytest.fixture
def client_keys(customizer, tmp_path, monkeypatch):
    keys = tmp_path / "client.keys"
    monkeypatch.setattr(customizer, "WAZUH_AGENT_CLIENT_KEYS_FILE", str(keys))
    return keys


@pytest.fixture
def run_command(customizer, monkeypatch):
    mock = MagicMock(return_value="")
    monkeypatch.setattr(customizer, "run_command", mock)
    return mock


@pytest.fixture
def curl(customizer, monkeypatch):
    """Stands in for both curl calls: the login returns a JWT, the DELETE returns `delete_response`."""

    calls = []
    delete_response = {"data": {"affected_items": ["001"], "total_affected_items": 1, "failed_items": []}}

    def fake_run(args, input, **_):
        calls.append((args, input))
        stdout = "the-jwt" if "POST" in args else json.dumps(delete_response)
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(customizer.subprocess, "run", fake_run)
    monkeypatch.setattr(customizer, "read_credential", lambda _: "the-password")
    return calls, delete_response


@pytest.fixture
def remove_previous_agent(customizer, monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr(customizer, "remove_previous_agent", mock)
    return mock


def test_reset_removes_the_anchor_marker_but_leaves_client_keys(customizer, client_keys, run_command):
    customizer.reset_agent_enrollment_state()

    command = run_command.call_args.kwargs["command"]
    assert customizer.WAZUH_AGENT_ANCHOR_COMMITTED_FILE in command
    assert str(client_keys) not in command  # a run failing before reset_agent_identity() keeps the ID


def test_reset_agent_identity_removes_the_previous_agent_before_emptying_client_keys(
    customizer, client_keys, run_command, remove_previous_agent
):
    client_keys.write_text("001 wazuh any 0123456789abcdef\n")
    remove_previous_agent.side_effect = lambda _: run_command.assert_not_called()

    customizer.reset_agent_identity()

    remove_previous_agent.assert_called_once_with("001")
    assert str(client_keys) in run_command.call_args.kwargs["command"]


def test_reset_agent_identity_only_empties_client_keys_on_a_normal_first_boot(
    customizer, client_keys, run_command, remove_previous_agent
):
    client_keys.write_text("")

    customizer.reset_agent_identity()

    remove_previous_agent.assert_called_once_with(None)
    run_command.assert_called_once()


def test_reset_agent_identity_does_nothing_without_client_keys(
    customizer, client_keys, run_command, remove_previous_agent
):
    customizer.reset_agent_identity()

    remove_previous_agent.assert_not_called()
    run_command.assert_not_called()


def test_remove_previous_agent_does_nothing_without_a_previous_agent(customizer, curl):
    calls, _ = curl

    customizer.remove_previous_agent(None)

    assert calls == []


def test_remove_previous_agent_ignores_an_id_that_is_not_numeric(customizer, curl):
    calls, _ = curl

    customizer.remove_previous_agent("001&agents_list=all")

    assert calls == []


def test_remove_previous_agent_deletes_it_through_the_api(customizer, curl):
    calls, _ = curl

    customizer.remove_previous_agent("001")

    (login_args, login_input), (delete_args, delete_input) = calls
    assert "the-password" in login_input and "the-password" not in " ".join(login_args)
    assert "the-jwt" in delete_input and "the-jwt" not in " ".join(delete_args)
    assert "DELETE" in delete_args
    assert delete_args[-1].endswith("/agents?agents_list=001&status=all&older_than=0s&purge=true")


def test_remove_previous_agent_warns_but_does_not_raise_when_the_delete_fails(customizer, curl):
    _, delete_response = curl
    delete_response["data"]["total_affected_items"] = 0

    with patch.object(customizer, "logger") as mock_logger:
        customizer.remove_previous_agent("001")

    mock_logger.warning.assert_called_once()
