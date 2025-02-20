from typing import List

from pydantic import AnyUrl


def check_correct_url(url: AnyUrl, allowed_hosts: List[str]) -> bool:
    """
    Check if the given URL belongs to one of the allowed hosts.
    Args:
        url (AnyUrl): The URL to be checked.
        allowed_hosts (List[str]): A list of allowed hostnames.
    Returns:
        bool: True if the URL belongs to one of the allowed hosts, False otherwise.
    """
    
    return any(host in str(url) for host in allowed_hosts)
