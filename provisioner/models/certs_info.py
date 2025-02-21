import pydantic_core
from pydantic import AnyUrl, BaseModel

from provisioner.utils import AllowedUrlHost, CertificatesComponent
from utils import Logger

from .utils import check_correct_url

logger = Logger("Certificates provision")


class CertsInfo(BaseModel):
    """
    CertsInfo is a model that holds information about certificate URLs.

    Attributes:
        certs_url_content (dict): A dictionary containing URLs for the cert-tool and config components.

    Properties:
        certs_tool_url (AnyUrl): Retrieves the URL for the cert-tool component.
        config_url (AnyUrl): Retrieves the configuration URL for the config file.
    """
    certs_url_content: dict

    @property
    def certs_tool_url(self) -> AnyUrl:
        return self._get_url_by_name(CertificatesComponent.CERTS_TOOL)

    @property
    def config_url(self) -> AnyUrl:
        return self._get_url_by_name(CertificatesComponent.CONFIG)

    def _get_url_by_name(self, name: str) -> AnyUrl:
        """
        Retrieve the URL for a certificates component (cert-tool or config).

        Returns:
            AnyUrl: The URL associated with the component.
        """
        logger.debug(f"Getting URL for {name}...")
        try:
            url = AnyUrl(self.certs_url_content.get(name, None))
        except pydantic_core._pydantic_core.ValidationError as err:
            raise ValueError(f"URL for {name} has an invalid format.") from err

        if not check_correct_url(
            url,
            [AllowedUrlHost.RELEASE, AllowedUrlHost.PRE_RELEASE, AllowedUrlHost.INTERNAL],
        ):
            raise ValueError(f"URL for {name} is not for Wazuh packages.")

        return url
