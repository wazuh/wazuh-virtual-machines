import json
import os
import re
import subprocess

import yaml


def set_wazuh_major_and_version(input_file: str, wazuh_major: str, wazuh_version: str, commit_list: list[str]) -> None:
    """
    Set the Wazuh major and version variables based on the Wazuh version in the artifacts urls passed as an
    `input_file` parameter.
    
    Args:
        input_file (str): The path to the input file.
        wazuh_major (str): The Wazuh major version.
        wazuh_version (str): The Wazuh version.
        commit_list (list[str]): A list of commit hashes.
        
    Returns:
        None
    """

    indexer_commit = commit_list[0]
    server_commit = commit_list[1]
    dashboard_commit = commit_list[2]
    replacements = {
        r"MAJOR": wazuh_major,
        r"WAZUH_VERSION": wazuh_version,
        r'(wazuh-indexer[^\s]*?)(\d+\.\d+\.\d+)-latest': rf'\1\2-{indexer_commit}',
        r'(wazuh-server[^\s]*?)(\d+\.\d+\.\d+)-latest': rf'\1\2-{server_commit}',
        r'(wazuh-dashboard[^\s]*?)(\d+\.\d+\.\d+)-latest': rf'\1\2-{dashboard_commit}',
    }

    with open(input_file) as file:
        content = file.read()

    for key, value in replacements.items():
        content = re.sub(key, value, content)

    with open(input_file, "w") as file:
        file.write(content)


def replace_url_by_its_signed(input_file: str) -> None:
    """
    Replace the URLs in the input file with their presigned versions using AWS CLI.
    
    Args:
        input_file (str): The path to the input file.
        
    Returns:
        None
    """

    with open(input_file) as file:
        content = yaml.safe_load(file)
    
    for key, value in content.items():
        command = f"aws s3 presign {value} --region us-west-1"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout
        error_output = result.stderr
        
        if error_output:
            raise RuntimeError(f"Error generating presigned URL for {key}: {error_output}")
        
        content[key] = output.strip()

    with open(input_file, "w") as file:
        yaml.dump(content, file, default_flow_style=False)


if __name__ == "__main__":
    INPUT_FILE = os.getenv("LOCAL_ARTIFACTS_URLS_FILEPATH")
    WAZUH_VERSION = os.getenv("WAZUH_VERSION")
    COMMIT_LIST = os.getenv("COMMIT_LIST")
    
    if not COMMIT_LIST:
        raise ValueError("COMMIT_LIST environment variable is not set.")
    if not INPUT_FILE:
        raise ValueError("LOCAL_ARTIFACTS_URLS_FILEPATH environment variable is not set.")
    if not WAZUH_VERSION:
        raise ValueError("WAZUH_VERSION environment variable is not set.")

    COMMIT_LIST = re.sub(r'(\w+)', r'"\1"', COMMIT_LIST)
    WAZUH_MAJOR = WAZUH_VERSION.split(".")[0]

    set_wazuh_major_and_version(input_file=INPUT_FILE, wazuh_major=WAZUH_MAJOR, wazuh_version=WAZUH_VERSION, commit_list=json.loads(COMMIT_LIST))
    replace_url_by_its_signed(input_file=INPUT_FILE)
    