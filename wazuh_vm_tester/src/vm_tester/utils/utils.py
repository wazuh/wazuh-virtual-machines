"""
Utility module for working with Ansible inventory files.
"""

import logging
import os
import subprocess
import threading

import boto3
import yaml

logger = logging.getLogger(__name__)


def read_ansible_inventory(inventory_path: str) -> dict:
    """Read and parse an Ansible inventory file.

    Args:
        inventory_path: Path to the Ansible inventory file

    Returns:
        Dictionary with the parsed inventory content

    Raises:
        FileNotFoundError: If the inventory file does not exist
        ValueError: If the inventory file cannot be parsed
    """
    if not os.path.exists(inventory_path):
        raise FileNotFoundError(f"Ansible inventory file not found: {inventory_path}")

    try:
        with open(inventory_path) as f:
            inventory_content = yaml.safe_load(f)
            return inventory_content
    except Exception as e:
        raise ValueError(f"Error parsing Ansible inventory file: {e}")


def get_host_connection_info(inventory_path: str, host_id: str | None = None) -> dict:
    """Extract connection information for a host from an Ansible inventory.

    Args:
        inventory_path: Path to the Ansible inventory file
        host_id: Optional host ID to extract information for. If not provided,
                 the first host in the inventory will be used.

    Returns:
        Dictionary with connection information for the host

    Raises:
        ValueError: If the host is not found in the inventory or if required connection
                    information is missing
    """
    inventory = read_ansible_inventory(inventory_path)

    if "all" not in inventory or "hosts" not in inventory["all"]:
        raise ValueError("Invalid Ansible inventory format: 'all.hosts' section is missing")

    hosts = inventory["all"]["hosts"]
    if not hosts:
        raise ValueError("No hosts found in the Ansible inventory")

    if host_id:
        if host_id not in hosts:
            raise ValueError(f"Host '{host_id}' not found in the Ansible inventory")
        host_info = hosts[host_id]
        host_info["id"] = host_id
    else:
        host_id = next(iter(hosts))
        host_info = hosts[host_id]
        host_info["id"] = host_id

    required_fields = ["ansible_host", "ansible_user"]
    missing_fields = [field for field in required_fields if field not in host_info]

    if missing_fields:
        raise ValueError(f"Missing required fields in host configuration: {', '.join(missing_fields)}")

    connection_info = {
        "host_id": host_info["id"],
        "hostname": host_info["ansible_host"],
        "username": host_info["ansible_user"],
        "port": host_info.get("ansible_port", 22),
        "ssh_key_file": host_info.get("ansible_ssh_private_key_file"),
        "ssh_common_args": host_info.get("ansible_ssh_common_args", ""),
    }

    return connection_info


def list_hosts_in_inventory(inventory_path: str) -> list[str]:
    """List all hosts in an Ansible inventory file.

    Args:
        inventory_path: Path to the Ansible inventory file

    Returns:
        List of host IDs in the inventory
    """
    inventory = read_ansible_inventory(inventory_path)

    if "all" not in inventory or "hosts" not in inventory["all"]:
        return []

    return list(inventory["all"]["hosts"].keys())


import sys
import time


def simple_progress_bar(total_seconds):
    for i in range(total_seconds + 1):
        progress = i / total_seconds
        bar_length = 40
        filled_length = int(bar_length * progress)
        bar = "█" * filled_length + "░" * (bar_length - filled_length)
        percent = progress * 100

        sys.stdout.write(f"\r[{bar}] {percent:.1f}% ({i}/{total_seconds} seconds)")
        sys.stdout.flush()
        time.sleep(1)
    print()


def digital_clock(total_seconds):
    """Display a digital clock progress bar.

    Args:
        total_seconds (int): Total estimated seconds for the operation
    """
    start_time = time.time()
    for remaining in range(total_seconds, -1, -1):
        elapsed = time.time() - start_time
        percent = ((total_seconds - remaining) / total_seconds) * 100
        elapsed_formatted = time.strftime("%M:%S", time.gmtime(elapsed))
        remaining_formatted = time.strftime("%M:%S", time.gmtime(remaining))
        progress = (total_seconds - remaining) / total_seconds
        bar_length = 50
        filled_length = int(bar_length * progress)
        bar = "█" * filled_length + "░" * (bar_length - filled_length)

        sys.stdout.write(f"\r[{bar}] {percent:.1f}% | Elapsed: {elapsed_formatted} | Remaining: {remaining_formatted}")
        sys.stdout.flush()

        time.sleep(1)
    print()


def spinner_clock(total_seconds):
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    start_time = time.time()

    for i in range(total_seconds):
        elapsed = time.time() - start_time
        remaining = total_seconds - i
        percent = (i / total_seconds) * 100
        spinner_char = spinner[i % len(spinner)]

        elapsed_formatted = time.strftime("%M:%S", time.gmtime(elapsed))
        remaining_formatted = time.strftime("%M:%S", time.gmtime(remaining))

        sys.stdout.write(
            f"\r{spinner_char} Waiting for AWS instance: {percent:.1f}% | {elapsed_formatted}/{time.strftime('%M:%S', time.gmtime(total_seconds))} | Remaining: {remaining_formatted}"
        )
        sys.stdout.flush()
        time.sleep(1)
    print()


def tqdm_progress(total_seconds):
    try:
        from tqdm import tqdm

        for _ in tqdm(
            range(total_seconds),
            desc="Waiting for AWS instance",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [Time: {elapsed}<{remaining}]",
        ):
            time.sleep(1)
    except ImportError:
        simple_progress_bar(total_seconds)


def show_progress(duration_seconds, operation_name, is_completed_func):
    """
    Displays a progress bar and updates based on the status of the operation.

     Args:
         duration_seconds: Estimated duration in seconds
         operation_name: Name of the operation to display
         is_completed_func: Function that returns True when the operation is complete

     Returns:
         The elapsed time in seconds
    """
    start_time = time.time()
    for remaining in range(duration_seconds, -1, -1):
        if is_completed_func():
            elapsed = time.time() - start_time
            elapsed_formatted = time.strftime("%M:%S", time.gmtime(elapsed))
            percent = 100.0
            bar_length = 50
            bar = "█" * bar_length

            sys.stdout.write(f"\r[{bar}] {percent:.1f}% | {operation_name} completed in {elapsed_formatted}")
            sys.stdout.flush()
            print()
            return elapsed

        elapsed = time.time() - start_time
        percent = ((duration_seconds - remaining) / duration_seconds) * 100
        elapsed_formatted = time.strftime("%M:%S", time.gmtime(elapsed))
        remaining_formatted = time.strftime("%M:%S", time.gmtime(remaining))
        progress = (duration_seconds - remaining) / duration_seconds
        bar_length = 50
        filled_length = int(bar_length * progress)
        bar = "█" * filled_length + "░" * (bar_length - filled_length)

        sys.stdout.write(
            f"\r[{bar}] {percent:.1f}% | {operation_name} | Elapsed: {elapsed_formatted} | Remaining: {remaining_formatted}"
        )
        sys.stdout.flush()

        time.sleep(1)

    return time.time() - start_time


def wait_for_completion(operation_name, is_completed_func):
    """
    Waits for an operation to complete, displaying a spinner.

    Args:
        operation_name: Name of the operation
        is_completed_func: Function that returns True when the operation is complete

    Returns:
        The additional time elapsed in seconds
    """
    print(f"\n{operation_name} is taking longer than expected, please wait...")

    start_time = time.time()
    spinner = ["|", "/", "-", "\\"]
    i = 0
    while not is_completed_func():
        sys.stdout.write(f"\rWaiting for completion... {spinner[i % len(spinner)]}")
        sys.stdout.flush()
        time.sleep(0.5)
        i += 1

    print(f"\n{operation_name} completed")
    return time.time() - start_time


def run_with_progress(func, args=(), kwargs=None, duration_seconds=360, operation_name="Operation"):
    """
    Executes a function in a separate thread while displaying a progress bar.
    If the function completes before the estimated time, the progress bar stops.
    If the function takes longer, it waits for it to complete.

    Args:
        func: The function to execute
        args: Positional arguments for the function
        kwargs: Named arguments for the function
        duration_seconds: Estimated duration in seconds for the progress bar
        operation_name: Name of the operation for logging

    Returns:
        The result of the function
    """
    if kwargs is None:
        kwargs = {}
    thread_completed = False
    thread_result = [None]
    thread_exception = [None]

    def thread_wrapper():
        try:
            result = func(*args, **kwargs)
            thread_result[0] = result
        except Exception as e:
            thread_exception[0] = e
        finally:
            nonlocal thread_completed
            thread_completed = True

    print(f"Starting {operation_name}...")
    logger.info(f"Starting {operation_name}")

    thread = threading.Thread(target=thread_wrapper)
    thread.start()

    def is_completed():
        return thread_completed

    elapsed = show_progress(duration_seconds, operation_name, is_completed)

    if not thread_completed:
        additional_time = wait_for_completion(operation_name, is_completed)
        elapsed += additional_time

    thread.join()

    if thread_exception[0]:
        logger.error(f"Error in {operation_name}: {str(thread_exception[0])}")
        raise thread_exception[0]

    elapsed_formatted = time.strftime("%M:%S", time.gmtime(elapsed))
    print(f"{operation_name} completed successfully in {elapsed_formatted}")

    return thread_result[0]


def download_s3_file(bucket_name, key, local_path):
    """Download a file from S3 to a local path.

    Args:
        bucket_name (str): S3 bucket name
        key (str): S3 object key
        local_path (str): Local file path to save to

    Returns:
        bool: True if successful
    """
    try:
        s3_client = boto3.client("s3")
        s3_client.download_file(bucket_name, key, local_path)
        return True
    except Exception as e:
        logger.error(f"S3 download error: {str(e)}")
        return False


def run_scp_command(scp_cmd):
    """Run an SCP command to transfer a file.

    Args:
        scp_cmd (list): SCP command as a list of arguments

    Returns:
        bool: True if successful
    """
    try:
        result = subprocess.run(scp_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"SCP error: {result.stderr}")
            return False
        return True
    except Exception as e:
        logger.error(f"SCP execution error: {str(e)}")
        return False
