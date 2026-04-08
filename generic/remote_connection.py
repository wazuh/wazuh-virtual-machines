from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from models import Inventory

from contextlib import contextmanager
from typing import Union

import paramiko

from utils import Logger

logger = Logger("Instance connection")


@contextmanager
def get_client(inventory: Union["Inventory", None] = None):
    """
    Establishes an SSH connection to a remote host using the provided inventory details.

    Args:
        inventory (Inventory): An object containing the connection details such as hostname, username, port,
                               password, and private key file.

    Yields:
        paramiko.SSHClient: An active SSH client connection if the inventory is provided.
        None: If no inventory is provided, indicating a local connection.
    """
    if not inventory:
        logger.warning("No inventory provided. Using local connection")
        yield None
    else:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=inventory.ansible_host,
                username=inventory.ansible_user,
                port=inventory.ansible_port,
                password=inventory.ansible_password.get_secret_value() if inventory.ansible_password else None,
                key_filename=str(inventory.ansible_ssh_private_key_file),
            )
            logger.info_success(f"Connected to host {inventory.ansible_host} with user {inventory.ansible_user}")

            yield client
        finally:
            logger.info_success(f"Closing connection to host {inventory.ansible_host}")
            client.close()


def remote_connection(func):
    def wrapper(self, *args, **kwargs):
        with get_client(self.inventory) as client:
            return func(self, *args, **kwargs, client=client)

    return wrapper
