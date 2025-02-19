from pydantic import AnyUrl, BaseModel
import pydantic_core
from provisioner.utils import AllowedUrlHost
from .utils import check_correct_url

from utils import Logger

logger = Logger("Certificates provision")

class CertsInfo(BaseModel):
    certs_url_content: dict
    
    @property
    def certs_tool_url(self) -> AnyUrl:
        return self._get_url_by_name("certs_tool")
        
    @property
    def config_url(self) -> AnyUrl:
        return self._get_url_by_name("config")
        
    def _get_url_by_name(self, name: str) -> AnyUrl:
        logger.debug(f"Getting URL for {name}...")
        try:
            url = AnyUrl(self.certs_url_content.get(name, None))
        except pydantic_core._pydantic_core.ValidationError:
            raise ValueError(f"URL for {name} has an invalid format.")

        if url is None:
            raise TypeError(f"{name} not found in certificates. Expected an URL but got None.")
        
        if not check_correct_url(url, [AllowedUrlHost.RELEASE, AllowedUrlHost.PRE_RELEASE, AllowedUrlHost.INTERNAL]):
            raise ValueError(f"URL for {name} is not for Wazuh packages.")

        return url
