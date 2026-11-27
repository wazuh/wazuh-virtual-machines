import argparse
import os
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

import yaml

SECRET_PARAMS = {"X-Amz-Signature", "X-Amz-Security-Token", "X-Amz-Credential"}


def fail(message: str) -> None:
    print(f"::error::{message}", flush=True)
    sys.exit(1)


def mask(value: str, emitted: set) -> None:
    if value and value not in emitted:
        emitted.add(value)
        print("::add-mask::" + value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A"), flush=True)


def object_key_of(url: str, host_pattern: re.Pattern, prefix: str):
    parts = urlsplit(url)
    match = host_pattern.match(parts.netloc)
    object_key = unquote(parts.path).lstrip("/")
    segments = object_key.split("/")
    if (
        parts.scheme != "https"
        or not match
        or parts.query
        or parts.fragment
        or not object_key.startswith(prefix + "/")
        or "" in segments
        or ".." in segments
        or "." in segments
    ):
        return None
    return match.group(1), object_key


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--expires-in", type=int, default=2700)
    args = parser.parse_args()

    bucket = os.environ.get("PRIVATE_BUCKET", "")
    if not bucket or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        fail("PRIVATE_BUCKET is not set or is not a valid bucket name")
    prefix = args.prefix.strip("/")
    if not prefix or ".." in prefix.split("/"):
        fail("The prefix is not valid")
    if not 0 < args.expires_in <= 604800:
        fail("The expiration is not valid")
    host_pattern = re.compile(rf"{re.escape(bucket)}\.s3\.([a-z0-9-]+)\.amazonaws\.com")

    try:
        with open(args.path) as file:
            content = yaml.safe_load(file)
    except (OSError, yaml.YAMLError):
        fail("The artifact URLs file cannot be read as YAML")
    if not isinstance(content, dict) or not content:
        fail("The artifact URLs file is empty or has an unexpected format")

    targets = {}
    for index, (key, value) in enumerate(content.items(), start=1):
        target = object_key_of(value, host_pattern, prefix) if isinstance(value, str) else None
        if target is None:
            fail(f"Entry {index} is not an https object of the expected bucket and prefix")
        targets[key] = target

    emitted: set = set()
    for value in content.values():
        mask(value, emitted)
    signed = {}
    for index, (key, (region, object_key)) in enumerate(targets.items(), start=1):
        result = subprocess.run(
            ["aws", "s3", "presign", f"s3://{bucket}/{object_key}", "--region", region, "--expires-in", str(args.expires_in)],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        url = result.stdout.strip()
        mask(url, emitted)
        mask(url.split("?")[0], emitted)
        if result.returncode != 0 or not url:
            fail(f"Could not presign entry {index}")
        query = urlsplit(url).query
        mask(query, emitted)
        for pair in query.split("&"):
            name, _, raw_value = pair.partition("=")
            if name in SECRET_PARAMS:
                mask(raw_value, emitted)
                mask(unquote(raw_value), emitted)
        signed[key] = url

    if list(signed) != list(content):
        fail("The signed entries do not match the input entries")
    for index, url in enumerate(signed.values(), start=1):
        parts = urlsplit(url)
        names = {pair.partition("=")[0] for pair in parts.query.split("&")}
        if object_key_of(url.split("?")[0], host_pattern, prefix) is None or "X-Amz-Signature" not in names:
            fail(f"Entry {index} is not signed")

    temporary = f"{args.path}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as file:
        yaml.safe_dump(signed, file, default_flow_style=False, sort_keys=False)
    os.chmod(temporary, 0o600)
    os.replace(temporary, args.path)
    print(f"Presigned {len(signed)} of {len(content)} URLs (not printed)")


if __name__ == "__main__":
    main()
