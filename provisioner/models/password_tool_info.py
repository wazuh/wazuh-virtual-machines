from pydantic import AnyUrl, BaseModel, field_validator

from provisioner.utils import AllowedUrlHost
from utils import Logger

from .utils import check_correct_url

logger = Logger("Password-tool provision")


class PasswordToolInfo(BaseModel):
    """
    PasswordToolInfo is a model that holds information about password tool URL.

    Attributes:
        password_tool_url (str): A string containing the URL for the password-tool.
    """

    password_tool_url: AnyUrl

    @field_validator("password_tool_url")
    def validate_password_tool_url(cls, url: AnyUrl) -> AnyUrl:
        logger.debug("Validating password tool URL...")
        if not check_correct_url(
            url,
            [AllowedUrlHost.RELEASE, AllowedUrlHost.PRE_RELEASE, AllowedUrlHost.INTERNAL],
        ):
            raise ValueError("URL for password-tool is not for Wazuh packages.")

        return url
