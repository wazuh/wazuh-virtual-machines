"""
Connection strategies for Wazuh VM Tester.
"""

from .ami import AMIStrategy
from .ansible import AnsibleStrategy
from .base import ConnectionStrategy
from .factory import StrategyFactory
from .local import LocalStrategy
from .ssh import SSHStrategy

__all__ = [
    "ConnectionStrategy",
    "LocalStrategy",
    "SSHStrategy",
    "AnsibleStrategy",
    "AMIStrategy",
    "StrategyFactory",
]
