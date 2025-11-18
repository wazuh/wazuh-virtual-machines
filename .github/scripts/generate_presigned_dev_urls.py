import json
import os
import re
import subprocess

import yaml


def get_github_env_variables(commit_list: list[str]) -> tuple[dict[str, str], list[str]]:
    # Extract commits from the list
    indexer_commit = commit_list[0] if len(commit_list) > 0 else "latest"
    server_commit = commit_list[1] if len(commit_list) > 1 else "latest"
    dashboard_commit = commit_list[2] if len(commit_list) > 2 else "latest"
    agent_commit = commit_list[3] if len(commit_list) > 3 else "latest"

    # Get environment variables (variable names in artifacts_urls.yaml: variable names in GitHub Actions)
    env_vars = {
        "AWS_S3_BUCKET_DEV": os.getenv("LOCAL_AWS_S3_BUCKET_DEV"),
        "MAJOR": os.getenv("WAZUH_MAJOR"),
        "WAZUH_VERSION": os.getenv("WAZUH_VERSION"),
        "MANAGER_REVISION": server_commit,  # Use actual commit from list
        "INDEXER_REVISION": indexer_commit,
        "DASHBOARD_REVISION": dashboard_commit,
        "AGENT_REVISION": agent_commit,
        "OVA_REVISION": os.getenv("INPUT_OVA_REVISION", "0"),
    }

    # Validate required variables
    required_vars = ["AWS_S3_BUCKET_DEV", "MAJOR", "WAZUH_VERSION"]
    missing_vars = []

    for var in required_vars:
        if not env_vars[var]:
            missing_vars.append(var)

    return env_vars, missing_vars


def expand_github_variables(input_file: str, commit_list: list[str]) -> None:
    """
    Expand GitHub Actions variables and environment variables in the artifacts URLs file.

    Args:
        input_file (str): The path to the input file.
        commit_list (list[str]): A list of commit hashes.

    Returns:
        None
    """

    with open(input_file) as file:
        content = file.read()

    env_vars, missing_vars = get_github_env_variables(commit_list)

    if missing_vars:
        raise ValueError(f"Required environment variables are missing: {missing_vars}. Cannot proceed.")

    # Replace GitHub Actions variables like ${{ vars.AWS_S3_BUCKET_DEV }}
    if env_vars["AWS_S3_BUCKET_DEV"]:
        content = re.sub(r"\$\{\{\s*vars\.AWS_S3_BUCKET_DEV\s*\}\}", env_vars["AWS_S3_BUCKET_DEV"], content)

    # Replace GitHub Actions environment variables like ${{ env.MAJOR }}
    for var_name, var_value in env_vars.items():
        if var_value:  # Only replace if we have a value
            pattern = r"\$\{\{\s*env\." + var_name + r"\s*\}\}"
            content = re.sub(pattern, var_value, content)

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
        command = f"aws s3 presign {value} --region us-west-1 --expires-in 18000"  # 5 hours
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
    COMMIT_LIST = os.getenv("COMMIT_LIST")

    if not COMMIT_LIST:
        raise ValueError("COMMIT_LIST environment variable is not set.")
    if not INPUT_FILE:
        raise ValueError("LOCAL_ARTIFACTS_URLS_FILEPATH environment variable is not set.")

    expand_github_variables(input_file=INPUT_FILE, commit_list=json.loads(COMMIT_LIST))

    replace_url_by_its_signed(input_file=INPUT_FILE)
