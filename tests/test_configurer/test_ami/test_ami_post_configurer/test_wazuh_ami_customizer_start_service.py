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
    """Loads wazuh-ami-customizer.py as a module (see test_wazuh_ami_customizer_certs_tar.py)."""

    spec = importlib.util.spec_from_file_location("wazuh_ami_customizer_start_service", CUSTOMIZER_PATH)
    module = importlib.util.module_from_spec(spec)
    with patch("logging.FileHandler", return_value=logging.NullHandler()):
        spec.loader.exec_module(module)
    return module


def test_start_service_logs_the_prestart_reason_before_raising(customizer, monkeypatch):
    monkeypatch.setattr(customizer, "run_command", MagicMock(side_effect=RuntimeError("Error starting wazuh-manager")))
    journal = MagicMock(return_value=("MISSING WAZUH_INDEXER_MANAGER_PASSWORD\n", "", 0))
    monkeypatch.setattr(customizer, "exec_command_with_status", journal)
    error_log = MagicMock()
    monkeypatch.setattr(customizer.logger, "error", error_log)

    with pytest.raises(RuntimeError):
        customizer.start_service("wazuh-manager")

    command = journal.call_args.kwargs["command"]
    assert "journalctl -u wazuh-manager -n 50" in command
    assert "MISSING|INVALID|UNSAFE" in command
    assert "MISSING WAZUH_INDEXER_MANAGER_PASSWORD" in error_log.call_args.args[0]


def test_start_service_does_not_read_the_journal_when_the_service_starts(customizer, monkeypatch):
    monkeypatch.setattr(customizer, "run_command", MagicMock(return_value=""))
    journal = MagicMock()
    monkeypatch.setattr(customizer, "exec_command_with_status", journal)

    customizer.start_service("wazuh-indexer")

    journal.assert_not_called()
