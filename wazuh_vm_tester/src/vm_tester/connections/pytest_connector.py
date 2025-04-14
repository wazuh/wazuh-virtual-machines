"""
Connection handler for pytest integrations.
"""

from typing import Optional

from ..config import get_logger
from .base import ConnectionInterface
from .local import LocalConnection

logger = get_logger(__name__)


class ConnectionRegistry:
    """Registry of active connections that can be accessed across modules."""

    _instance: Optional[ConnectionInterface] = None

    @classmethod
    def set_active_connection(cls, connection: ConnectionInterface) -> None:
        """Set the active connection for testing.

        Args:
            connection: Connection to use for testing
        """
        cls._instance = connection
        logger.debug(f"Set active connection: {connection.id}")

    @classmethod
    def get_active_connection(cls) -> Optional[ConnectionInterface]:
        """Get the currently active connection.

        Returns:
            Active connection instance or None if not set
        """
        if cls._instance is None:
            logger.warning("No active connection found, creating a local connection")
            local_connection = LocalConnection()
            local_connection.connect()
            cls._instance = local_connection

        return cls._instance


def get_connection() -> ConnectionInterface:
    """Get the active connection for test execution.

    Returns:
        Connection interface

    Raises:
        RuntimeError: If no connection can be established
    """
    connection = ConnectionRegistry.get_active_connection()
    if not connection:
        raise RuntimeError("No active connection available for testing")
    return connection
