"""
Local connection strategy implementation.
"""

from typing import Optional

from ..utils.logger import get_logger
from ..connections.base import ConnectionInterface
from ..connections.local import LocalConnection
from .base import ConnectionStrategy

logger = get_logger(__name__)


class LocalStrategy(ConnectionStrategy):
    """Strategy for local machine testing."""

    def create_connection(self) -> Optional[ConnectionInterface]:
        """Create a local connection.

        Returns:
            Local connection instance
        """
        logger.info("Creating local connection for testing")

        connection = LocalConnection()
        connection.connect()

        return connection

    def cleanup(self) -> None:
        """Clean up resources after testing (no-op for local)."""
        logger.info("Cleanup for local connection (no action needed)")
