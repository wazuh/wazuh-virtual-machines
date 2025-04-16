"""
Base connection interface for all connection types.
"""

from abc import ABC, abstractmethod
from typing import Tuple, Optional


class ConnectionInterface(ABC):
    """Abstract interface for all connection types."""

    @abstractmethod
    def connect(self, **kwargs) -> 'ConnectionInterface':
        """Establish connection to the target.

        Args:
            **kwargs: Connection parameters

        Returns:
            Self for method chaining
        """
        pass

    @abstractmethod
    def execute_command(self, command: str, sudo: bool = True) -> Tuple[int, str, str]:
        """Execute a command on the target.

        Args:
            command: Command to execute
            sudo: Whether to execute with sudo

        Returns:
            Tuple with (exit_code, stdout, stderr)
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """Close connection to the target."""
        pass

    @property
    @abstractmethod
    def id(self) -> str:
        """Get connection identifier."""
        pass

    @property
    def host(self) -> Optional[str]:
        """Get the host address."""
        return None

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(id={self.id})"
