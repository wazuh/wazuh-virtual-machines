"""
Connection strategies for Wazuh VM Tester.
"""

from .base import ConnectionStrategy
from .local import LocalStrategy
from .ssh import SSHStrategy
from .ansible import AnsibleStrategy
from .ami import AMIStrategy
from .factory import StrategyFactory

__all__ = [
    "ConnectionStrategy",
    "LocalStrategy",
    "SSHStrategy",
    "AnsibleStrategy",
    "AMIStrategy",
    "StrategyFactory",
]
