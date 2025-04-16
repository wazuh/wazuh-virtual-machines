"""
Base interface for instance types.
"""

from abc import ABC, abstractmethod
from typing import Tuple, Optional


class InstanceInterface(ABC):
    """Abstract interface for all instance types."""

    @abstractmethod
    def connect_ssh(self, **kwargs) -> 'InstanceInterface':
        """Establish connection to the instance.

        Args:
            **kwargs: Connection parameters

        Returns:
            Self for method chaining
        """
        pass

    @abstractmethod
    def execute_command(self, command: str, sudo: bool = True) -> Tuple[int, str, str]:
        """Execute a command on the instance.

        Args:
            command: Command to execute
            sudo: Whether to execute with sudo

        Returns:
            Tuple with (exit_code, stdout, stderr)
        """
        pass

    @abstractmethod
    def close_ssh(self) -> None:
        """Close connection to the instance."""
        pass

    @property
    @abstractmethod
    def instance_id(self) -> str:
        """Get the instance ID."""
        pass

    @property
    def public_ip(self) -> Optional[str]:
        """Get the public IP address."""
        return None

    @property
    def private_ip(self) -> Optional[str]:
        """Get the private IP address."""
        return None

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(id={self.instance_id})"
