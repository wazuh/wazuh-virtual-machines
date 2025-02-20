import pydantic_core
from pydantic import AnyUrl, BaseModel

from provisioner.utils import AllowedUrlHost, CertificatesComponent
from utils import Logger

from .utils import check_correct_url

logger = Logger("Certificates provision")

class CertsInfo(BaseModel):
    certs_url_content: dict
    
    @property
    def certs_tool_url(self) -> AnyUrl:
        return self._get_url_by_name(CertificatesComponent.CERTS_TOOL)
        
    @property
    def config_url(self) -> AnyUrl:
        return self._get_url_by_name(CertificatesComponent.CONFIG)
        
    def _get_url_by_name(self, name: str) -> AnyUrl:
        logger.debug(f"Getting URL for {name}...")
        try:
            url = AnyUrl(self.certs_url_content.get(name, None))
        except pydantic_core._pydantic_core.ValidationError as err:
            raise ValueError(f"URL for {name} has an invalid format.") from err

        if url is None:
            raise TypeError(f"{name} not found in certificates. Expected an URL but got None.")
        
        if not check_correct_url(url, [AllowedUrlHost.RELEASE, AllowedUrlHost.PRE_RELEASE, AllowedUrlHost.INTERNAL]):
            raise ValueError(f"URL for {name} is not for Wazuh packages.")

        return url
