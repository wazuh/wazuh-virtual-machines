
from pydantic import AnyUrl, BaseModel

from utils import Component


class ComponentInfo(BaseModel):
    """
    ComponentInfo model representing information about a Wazuh component.

    Attributes:
        name (Component): The name of the component.
        package_url (AnyUrl): The URL to the package of the component.
        dependencies (List[str]): A list of dependencies required by the component.
    """

    name: Component
    package_url: AnyUrl
    dependencies: list[str]
