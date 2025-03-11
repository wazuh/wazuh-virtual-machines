import pytest
from pydantic import AnyUrl

from provisioner.models import CertsInfo
from utils import CertificatesComponent


@pytest.mark.parametrize(
    "component, url",
    [
        (CertificatesComponent.CONFIG, "https://packages.wazuh.com/config"),
        (CertificatesComponent.CERTS_TOOL, "https://packages.wazuh.com/cert-tool"),
    ],
)
def test_valid_urls(component, url):
    certs_info = CertsInfo(certs_url_content={component: url})
    assert getattr(certs_info, f"{component.lower()}_url") == AnyUrl(url)


@pytest.mark.parametrize(
    "component, url, error_msg",
    [
        (
            CertificatesComponent.CONFIG,
            "invalid-url",
            "URL for config has an invalid format.",
        ),
        (
            CertificatesComponent.CONFIG,
            "https://incorrect-host.com/config",
            "URL for config is not for Wazuh packages.",
        ),
        (
            CertificatesComponent.CERTS_TOOL,
            "invalid-url",
            "URL for certs_tool has an invalid format.",
        ),
        (
            CertificatesComponent.CERTS_TOOL,
            "https://incorrect-host.com/cert-tool",
            "URL for certs_tool is not for Wazuh packages.",
        ),
    ],
)
def test_invalid_urls(component, url, error_msg):
    with pytest.raises(ValueError, match=error_msg):
        getattr(CertsInfo(certs_url_content={component: url}), f"{component.lower()}_url")
