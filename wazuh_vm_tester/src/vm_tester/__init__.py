"""
Wazuh VM Tester - Framework for validating Wazuh VMs using pytest.
"""

__version__ = "0.2.0"

from .config import AMITesterConfig, setup_logging, get_logger

__all__ = ["AMITesterConfig", "setup_logging", "get_logger"]
