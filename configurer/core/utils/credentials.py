"""
Credentials resolved by the Wazuh 5.0 packages (wazuh/wazuh-indexer#1928).

The indexer, manager and dashboard packages generate their own passwords and publish them to
/etc/wazuh/credentials.env, which is also the record the user reads them from. Nothing here ever
prints a password or passes one on a command line: a value read from the file goes to curl through
its standard input (`curl -K -`), and the file is parsed, never sourced.
"""

import re
from enum import StrEnum
from pathlib import Path

WAZUH_BASE_DIR = Path("/etc/wazuh")
CREDENTIALS_FILE = WAZUH_BASE_DIR / "credentials.env"
# Where this instance's own root CA lives past first boot. The shared credentials library expects it
# here (root:root 0700, root-ca.pem 0644, root-ca.key 0400), and keeping the key lets a leaf be
# reissued later without a new CA every enrolled agent would have to re-trust.
WAZUH_CA_DIR = WAZUH_BASE_DIR / "ca"

PURGE_BUILD_CREDENTIALS_SCRIPT = Path(__file__).resolve().parent.parent / "static" / "purge-build-credentials.sh"


class CredentialKey(StrEnum):
    INDEXER_ADMIN = "WAZUH_INDEXER_ADMIN_PASSWORD"
    INDEXER_KIBANASERVER = "WAZUH_INDEXER_KIBANASERVER_PASSWORD"
    INDEXER_MANAGER = "WAZUH_INDEXER_MANAGER_PASSWORD"
    MANAGER_API = "WAZUH_MANAGER_API_PASSWORD"
    MANAGER_WUI = "WAZUH_MANAGER_WUI_PASSWORD"


_LINE = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.*)$")


def parse_credentials(content: str) -> dict[str, str]:
    """
    Parses the KEY=VALUE lines of a credentials file, the way the packages' shared library reads it.

    Comments and blank lines are skipped, a value wrapped in single or double quotes is unwrapped,
    and the last assignment of a key wins.

    Args:
        content (str): The content of the credentials file.

    Returns:
        dict[str, str]: Every key found, with its value.
    """

    credentials = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _LINE.match(line)
        if not match:
            continue
        key, value = match.groups()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        credentials[key] = value
    return credentials


def read_credential(key: str, credentials_file: Path = CREDENTIALS_FILE) -> str:
    """
    Reads one password from the credentials file.

    Args:
        key (str): The key to read, e.g. CredentialKey.INDEXER_ADMIN.
        credentials_file (Path): The credentials file. Defaults to /etc/wazuh/credentials.env.

    Returns:
        str: The value of the key.

    Raises:
        KeyError: If the key is absent or empty. The message names the key, never a value.
    """

    value = parse_credentials(credentials_file.read_text()).get(str(key), "")
    if not value:
        raise KeyError(f"{key} is not set in {credentials_file}")
    return value


def credential_shell_expression(key: str, credentials_file: Path = CREDENTIALS_FILE) -> str:
    """
    Returns a shell command substitution that prints one password read from the credentials file.

    Meant to be assigned to a shell variable on the host that holds the file, so the value never
    travels back to the caller nor appears on a command line.

    Args:
        key (str): The key to read.
        credentials_file (Path): The credentials file. Defaults to /etc/wazuh/credentials.env.

    Returns:
        str: e.g. `$(sudo sed -n 's/^KEY=//p' /etc/wazuh/credentials.env | tail -n 1 | sed ...)`.
    """

    unquote = "sed -e 's/^\"\\(.*\\)\"$/\\1/' -e \"s/^'\\(.*\\)'$/\\1/\""
    return f"$(sudo sed -n 's/^{key}=//p' {credentials_file} | tail -n 1 | {unquote})"


def indexer_request_command(
    method: str,
    path: str,
    user: str = "admin",
    key: str = CredentialKey.INDEXER_ADMIN,
    url: str = "https://127.0.0.1:9200",
) -> str:
    """
    Builds a shell command that sends one request to the indexer as `user`, printing the HTTP code.

    The password is read from the credentials file into a variable and handed to curl through its
    standard input (`-K -`), the same as `curl -u user:password` without the password in argv.

    Args:
        method (str): The HTTP method, e.g. "DELETE".
        path (str): The path after the indexer URL, e.g. "wazuh-*".
        user (str): The indexer user. Defaults to "admin".
        key (str): The credentials key holding that user's password.
        url (str): The indexer base URL.

    Returns:
        str: The shell command.
    """

    return (
        f"WAZUH_PW={credential_shell_expression(key)}; "
        f"printf 'user = \"%s:%s\"\\n' '{user}' \"$WAZUH_PW\" | "
        f"sudo curl -s -k -K - -o /dev/null -w '%{{http_code}}' -X {method} '{url}/{path}'; "
        "unset WAZUH_PW"
    )


def purge_build_credentials_command(script: Path = PURGE_BUILD_CREDENTIALS_SCRIPT) -> str:
    """
    Builds the command that runs purge-build-credentials.sh as root, fed through a here-document.

    Feeding the script on stdin runs it the same way on the local OVA build and over the AMI
    build's SSH session, with nothing to copy to the host first.

    Args:
        script (Path): The script to run. Defaults to configurer/core/static/purge-build-credentials.sh.

    Returns:
        str: The command.
    """

    return f"sudo bash -s <<'WAZUH_PURGE_BUILD_CREDENTIALS'\n{script.read_text()}\nWAZUH_PURGE_BUILD_CREDENTIALS\n"
