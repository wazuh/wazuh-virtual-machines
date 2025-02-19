from typing import List

from pydantic import AnyUrl, BaseModel
from provisioner.utils import Component


class ComponentInfo(BaseModel):
    name: Component
    package_url: AnyUrl
    dependencies: List[str]
