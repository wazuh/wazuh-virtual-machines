"""
Base classes for connection and execution strategies.
"""

from abc import ABC, abstractmethod

from ..config import AMITesterConfig
from ..connections.base import ConnectionInterface
from ..utils.logger import get_logger

logger = get_logger(__name__)


class ConnectionStrategy(ABC):
    """Abstract base class for connection strategies."""

    def __init__(self, config: AMITesterConfig):
        """Initialize strategy with configuration.

        Args:
            config: Tester configuration
        """
        self.config = config

    @abstractmethod
    def create_connection(self) -> ConnectionInterface | None:
        """Create and return a connection.

        Returns:
            Connection instance or None if creation fails
        """
        pass

    @abstractmethod
    def cleanup(self) -> None:
        """Clean up resources after testing."""
        pass
