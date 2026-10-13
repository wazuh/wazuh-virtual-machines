from unittest.mock import patch

import pytest

from wazuh_local_ova.build_ova import get_ova_version
from wazuh_local_ova.enums import EnvironmentType


@pytest.mark.parametrize(
    "environment, expected_ova_version",
    [
        (EnvironmentType.RELEASE, "5.0.0"),
        (EnvironmentType.PRE_RELEASE, "5.0.0-rc1"),
        (EnvironmentType.DEV, "5.0.0-dev"),
    ],
)
@patch("wazuh_local_ova.build_ova.get_wazuh_stage", return_value="rc1")
def test_get_ova_version(mock_get_wazuh_stage, environment, expected_ova_version):
    assert get_ova_version(wazuh_version="5.0.0", environment=environment) == expected_ova_version
