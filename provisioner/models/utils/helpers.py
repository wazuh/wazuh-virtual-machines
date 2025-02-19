from typing import List
from pydantic import AnyUrl

def check_correct_url(url: AnyUrl, allowed_hosts: List[str]) -> bool:
    for host in allowed_hosts:
        if host in str(url):
            return True
    return False
