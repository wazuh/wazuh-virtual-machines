import base64
import hashlib

import pytest

PUBLIC_KEY_TAG = 6
USER_ID_TAG = 13
PUBLIC_SUBKEY_TAG = 14


def build_packet(tag: int, body: bytes, old_format: bool = False) -> bytes:
    if old_format:
        return bytes([0x80 | (tag << 2) | 1]) + len(body).to_bytes(2, "big") + body

    if len(body) < 192:
        length = bytes([len(body)])
    elif len(body) < 8384:
        length = bytes([((len(body) - 192) >> 8) + 192, (len(body) - 192) & 0xFF])
    else:
        length = b"\xff" + len(body).to_bytes(4, "big")
    return bytes([0xC0 | tag]) + length + body


def build_key_body(seed: int, size: int = 64, version: int = 4) -> bytes:
    # Version, creation time, algorithm (RSA) and some key material.
    return bytes([version]) + seed.to_bytes(4, "big") + b"\x01" + bytes([seed % 256]) * size


def build_armored_key(*packets: bytes, headers: str = "Version: test\n") -> str:
    data = base64.b64encode(b"".join(packets)).decode()
    lines = "\n".join(data[i : i + 64] for i in range(0, len(data), 64))
    return f"-----BEGIN PGP PUBLIC KEY BLOCK-----\n{headers}\n{lines}\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"


def get_fingerprint(body: bytes) -> str:
    return hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()


@pytest.fixture
def wazuh_key():
    """A key with a primary key, a user ID and a subkey, like the Wazuh one."""
    body = build_key_body(seed=1)
    armored_key = build_armored_key(
        build_packet(PUBLIC_KEY_TAG, body),
        build_packet(USER_ID_TAG, b"Wazuh.com (Wazuh Signing Key) <support@wazuh.com>"),
        build_packet(PUBLIC_SUBKEY_TAG, build_key_body(seed=2)),
    )
    return armored_key, get_fingerprint(body)


@pytest.fixture
def other_key():
    body = build_key_body(seed=3)
    return build_armored_key(build_packet(PUBLIC_KEY_TAG, body)), get_fingerprint(body)
