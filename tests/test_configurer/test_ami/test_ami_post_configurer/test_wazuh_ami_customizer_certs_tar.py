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
    """
    Loads wazuh-ami-customizer.py as a module. Its file name has a hyphen, so it cannot be imported
    with a plain `import`, and it opens its log file under /var/log at import time, which the test
    environment may not be allowed to write to.
    """

    spec = importlib.util.spec_from_file_location("wazuh_ami_customizer_under_test", CUSTOMIZER_PATH)
    module = importlib.util.module_from_spec(spec)
    with patch("logging.FileHandler", return_value=logging.NullHandler()):
        spec.loader.exec_module(module)
    return module


@pytest.fixture
def certs_tar(customizer, tmp_path, monkeypatch):
    tar = tmp_path / "wazuh-certificates.tar"
    tar.write_bytes(b"leaf private keys")
    monkeypatch.setattr(customizer, "WAZUH_CERTS_TAR", tar)
    return tar


@pytest.fixture
def stubbed_steps(customizer, monkeypatch):
    """Replaces everything create_certificates() calls, recording the order they run in."""

    calls = []
    certs_manager = MagicMock()
    certs_manager.generate_certificates.side_effect = lambda **_: calls.append("generate_certificates")
    monkeypatch.setattr(customizer, "CertsManager", MagicMock(return_value=certs_manager))
    monkeypatch.setattr(customizer, "get_manager_san_ips", lambda: ["10.0.0.1"])
    monkeypatch.setattr(
        customizer, "install_certificate_authority", lambda: calls.append("install_certificate_authority")
    )
    return certs_manager, calls


def test_remove_certs_tar_deletes_the_file(customizer, certs_tar):
    customizer.remove_certs_tar()

    assert not certs_tar.exists()


def test_remove_certs_tar_does_nothing_when_the_file_is_already_gone(customizer, certs_tar):
    certs_tar.unlink()

    customizer.remove_certs_tar()  # must not raise

    assert not certs_tar.exists()


def test_remove_certs_tar_logs_but_does_not_raise_when_deletion_fails(customizer, monkeypatch):
    failing_tar = MagicMock()
    failing_tar.unlink.side_effect = PermissionError("Operation not permitted")
    monkeypatch.setattr(customizer, "WAZUH_CERTS_TAR", failing_tar)

    with patch.object(customizer, "logger") as mock_logger:
        customizer.remove_certs_tar()  # raising here would replace the error that made the customization fail

    mock_logger.error.assert_called_once()
    assert "still holds the private keys" in mock_logger.error.call_args.args[0]


def test_create_certificates_removes_the_tar_after_installing_the_ca(customizer, certs_tar, stubbed_steps):
    _, calls = stubbed_steps
    seen_by_last_reader = []
    # install_certificate_authority() is the last reader of the tar: it must still be there for it.
    customizer.install_certificate_authority = lambda: (
        calls.append("install_certificate_authority"),
        seen_by_last_reader.append(certs_tar.exists()),
    )

    customizer.create_certificates()

    assert calls == ["generate_certificates", "install_certificate_authority"]
    assert seen_by_last_reader == [True]
    assert not certs_tar.exists()


def test_create_certificates_removes_the_tar_when_certificate_generation_fails(customizer, certs_tar, stubbed_steps):
    certs_manager, _ = stubbed_steps
    certs_manager.generate_certificates.side_effect = Exception("Error while compressing certificates")

    with pytest.raises(Exception, match="Error while compressing certificates"):
        customizer.create_certificates()

    assert not certs_tar.exists()


def test_create_certificates_removes_the_tar_when_installing_the_ca_fails(
    customizer, certs_tar, stubbed_steps, monkeypatch
):
    def failing_install():
        raise RuntimeError("Error installing the CA")

    monkeypatch.setattr(customizer, "install_certificate_authority", failing_install)

    with pytest.raises(RuntimeError, match="Error installing the CA"):
        customizer.create_certificates()

    assert not certs_tar.exists()
