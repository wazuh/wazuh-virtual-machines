import pytest
from pydantic import AnyUrl

from provisioner.models.utils.helpers import check_correct_url
from provisioner.utils import AllowedUrlHost


@pytest.mark.parametrize(
    "url",
    [
        "https://packages.wazuh.com/4.x/yum/",
        "https://packages-dev.wazuh.com/doing/tests"
        "htts://xdrsiem-packages-dev-internal"
        "https://packages.wazuh.com"
        "https://packages-dev.wazuh.com",
        "https://xdrsiem-packages-dev-internal",
    ],
)
def test_check_correct_url_with_correct_url(url: str):
    allowed_hosts = [allowed.value for allowed in AllowedUrlHost]
    assert check_correct_url(AnyUrl(url), allowed_hosts)


@pytest.mark.parametrize(
    "url",
    [
        "https://packages-bad.wazuh.com/doing/tests",
        "https://packages-dev-internal.wazuh.com",
        "https://google.com/packages-dev-internal",
    ],
)
def test_check_correct_url_with_incorrect_url(url: str):
    allowed_hosts = [allowed.value for allowed in AllowedUrlHost]
    assert not check_correct_url(AnyUrl(url), allowed_hosts)
