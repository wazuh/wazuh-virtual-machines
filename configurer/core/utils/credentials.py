"""
Credentials resolved by the Wazuh 5.0 packages (wazuh/wazuh-indexer#1928).

Since 5.0.0 RC 2 (wazuh/internal-devel-requests#7048) each package publishes the passwords it owns
in its own export/credentials.env, which is also the record the user reads them from: the indexer
those of its users, the manager those of the Server API. Nothing here ever
prints a password or passes one on a command line: a value read from the file goes to curl through
its standard input (`curl -K -`), and the file is parsed, never sourced.
"""

import re
from enum import StrEnum
from pathlib import Path

from .enums import WAZUH_MANAGER_CONF_DIR

INDEXER_CREDENTIALS_FILE = Path("/etc/wazuh-indexer/export/credentials.env")
MANAGER_CREDENTIALS_FILE = Path(WAZUH_MANAGER_CONF_DIR) / "export" / "credentials.env"

WAZUH_BASE_DIR = Path("/etc/wazuh")
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


def credentials_file_for(key: str) -> Path:
    """
    Returns the export/credentials.env of the package that owns a key.

    Args:
        key (str): A CredentialKey.

    Returns:
        Path: The manager's file for WAZUH_MANAGER_* keys, the indexer's for every other one.
    """

    return MANAGER_CREDENTIALS_FILE if str(key).startswith("WAZUH_MANAGER_") else INDEXER_CREDENTIALS_FILE


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


def read_credential(key: str, credentials_file: Path | None = None) -> str:
    """
    Reads one password from the credentials file.

    Args:
        key (str): The key to read, e.g. CredentialKey.INDEXER_ADMIN.
        credentials_file (Path | None): The credentials file. Defaults to the owner's (credentials_file_for).

    Returns:
        str: The value of the key.

    Raises:
        KeyError: If the key is absent or empty. The message names the key, never a value.
    """

    credentials_file = credentials_file or credentials_file_for(key)
    value = parse_credentials(credentials_file.read_text()).get(str(key), "")
    if not value:
        raise KeyError(f"{key} is not set in {credentials_file}")
    return value


def credential_shell_expression(key: str, credentials_file: Path | None = None) -> str:
    """
    Returns a shell command substitution that prints one password read from the credentials file.

    Meant to be assigned to a shell variable on the host that holds the file, so the value never
    travels back to the caller nor appears on a command line.

    Args:
        key (str): The key to read.
        credentials_file (Path | None): The credentials file. Defaults to the owner's (credentials_file_for).

    Returns:
        str: e.g. `$(sudo sed -n 's/^KEY=//p' /etc/wazuh-indexer/export/credentials.env | tail -n 1 | sed ...)`.
    """

    credentials_file = credentials_file or credentials_file_for(key)

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
    Builds the command that runs purge-build-credentials.sh as root on the host being built.

    The script is written to a temporary file on that host (through a here-document) and run from
    there, with its stdin from /dev/null. Running it with `bash -s` instead would make every command
    in it inherit the rest of the script as stdin: one that read it would swallow the remaining
    lines, and bash would exit 0 having silently skipped the workarounds and the final check. This
    runs the same way on the local OVA build and over the AMI build's SSH session.

    Args:
        script (Path): The script to run. Defaults to configurer/core/static/purge-build-credentials.sh.

    Returns:
        str: The command. Its exit status is the script's.
    """

    return (
        'WAZUH_PURGE_SCRIPT="$(mktemp)" || exit 1\n'
        "cat > \"${WAZUH_PURGE_SCRIPT}\" <<'WAZUH_PURGE_BUILD_CREDENTIALS'\n"
        f"{script.read_text()}\n"
        "WAZUH_PURGE_BUILD_CREDENTIALS\n"
        'sudo bash "${WAZUH_PURGE_SCRIPT}" < /dev/null\n'
        "WAZUH_PURGE_RC=$?\n"
        'rm -f "${WAZUH_PURGE_SCRIPT}"\n'
        'exit "${WAZUH_PURGE_RC}"\n'
    )
