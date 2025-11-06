"""
Wazuh VM Tester - Framework for validating Wazuh VMs using pytest.
"""

__version__ = "0.2.0"

from .config import AMITesterConfig
from .utils.logger import get_logger, setup_logging

__all__ = ["AMITesterConfig", "setup_logging", "get_logger"]
