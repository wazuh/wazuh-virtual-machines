from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from provisioner import Inventory

from contextlib import contextmanager

import paramiko

from utils import Logger

logger = Logger("Instance connection")

@contextmanager
def get_client(inventory: "Inventory"):
    if not inventory:
        logger.warning("No inventory provided. Using local connection")
        yield None
    else:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=inventory.ansible_host,
                            username=inventory.ansible_user,
                            port=inventory.ansible_port,
                            password=inventory.ansible_password.get_secret_value() if inventory.ansible_password else None,
                            key_filename=str(inventory.ansible_ssh_private_key_file))
            logger.info_success(f"Connected to host {inventory.ansible_host}")

            yield client
        except Exception as e:
            logger.error(f"Error connecting to host: {e}")
        finally:
            logger.info_success(f"Closing connection to host {inventory.ansible_host}")
            client.close()
    
def remote_connection(func):
    def wrapper(self, *args, **kwargs):
        with get_client(self.inventory) as client:
            return func(self, *args, **kwargs, client=client)
    return wrapper
