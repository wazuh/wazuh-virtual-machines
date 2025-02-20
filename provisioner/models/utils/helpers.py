from typing import List

from pydantic import AnyUrl


def check_correct_url(url: AnyUrl, allowed_hosts: List[str]) -> bool:
    return any(host in str(url) for host in allowed_hosts)
