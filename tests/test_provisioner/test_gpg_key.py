import pytest

from provisioner.utils.gpg_key import get_armored_key_bytes, get_gpg_key_fingerprint

from .conftest import (
    PUBLIC_KEY_TAG,
    PUBLIC_SUBKEY_TAG,
    build_armored_key,
    build_key_body,
    build_packet,
    get_fingerprint,
)


def test_get_gpg_key_fingerprint_success(wazuh_key):
    armored_key, fingerprint = wazuh_key

    assert get_gpg_key_fingerprint(armored_key) == fingerprint


@pytest.mark.parametrize("size", [10, 500, 9000])
def test_get_gpg_key_fingerprint_new_format_lengths(size):
    body = build_key_body(seed=1, size=size)

    assert get_gpg_key_fingerprint(build_armored_key(build_packet(PUBLIC_KEY_TAG, body))) == get_fingerprint(body)


def test_get_gpg_key_fingerprint_old_format_packets():
    body = build_key_body(seed=1)
    armored_key = build_armored_key(
        build_packet(PUBLIC_KEY_TAG, body, old_format=True),
        build_packet(PUBLIC_SUBKEY_TAG, build_key_body(seed=2), old_format=True),
    )

    assert get_gpg_key_fingerprint(armored_key) == get_fingerprint(body)


def test_get_gpg_key_fingerprint_without_armor_headers():
    body = build_key_body(seed=1)

    assert get_gpg_key_fingerprint(
        build_armored_key(build_packet(PUBLIC_KEY_TAG, body), headers="")
    ) == get_fingerprint(body)


def test_get_gpg_key_fingerprint_two_blocks(wazuh_key, other_key):
    with pytest.raises(ValueError, match="The key file must hold a single public key block"):
        get_gpg_key_fingerprint(wazuh_key[0] + other_key[0])


def test_get_gpg_key_fingerprint_no_block():
    with pytest.raises(ValueError, match="The key file must hold a single public key block"):
        get_gpg_key_fingerprint("<html>Not found</html>")


def test_get_gpg_key_fingerprint_two_primary_keys():
    armored_key = build_armored_key(
        build_packet(PUBLIC_KEY_TAG, build_key_body(seed=1)),
        build_packet(PUBLIC_KEY_TAG, build_key_body(seed=3)),
    )

    with pytest.raises(ValueError, match="The key must hold a single primary key, found 2"):
        get_gpg_key_fingerprint(armored_key)


def test_get_gpg_key_fingerprint_only_subkey():
    armored_key = build_armored_key(build_packet(PUBLIC_SUBKEY_TAG, build_key_body(seed=1)))

    with pytest.raises(ValueError, match="The key must hold a single primary key, found 0"):
        get_gpg_key_fingerprint(armored_key)


def test_get_gpg_key_fingerprint_not_v4():
    armored_key = build_armored_key(build_packet(PUBLIC_KEY_TAG, build_key_body(seed=1, version=3)))

    with pytest.raises(ValueError, match="The key is not a v4 OpenPGP key"):
        get_gpg_key_fingerprint(armored_key)


def test_get_gpg_key_fingerprint_truncated_packet():
    packet = build_packet(PUBLIC_KEY_TAG, build_key_body(seed=1))

    with pytest.raises(ValueError, match="The key holds a truncated OpenPGP packet"):
        get_gpg_key_fingerprint(build_armored_key(packet[:-10]))


def test_get_gpg_key_fingerprint_invalid_packet():
    with pytest.raises(ValueError, match="The key holds an invalid OpenPGP packet"):
        get_gpg_key_fingerprint(build_armored_key(b"\x01\x02\x03"))


def test_get_armored_key_bytes_invalid_base64():
    armored_key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnot*base64\n-----END PGP PUBLIC KEY BLOCK-----\n"

    with pytest.raises(ValueError, match="The key block is not valid base64"):
        get_armored_key_bytes(armored_key)


def test_get_armored_key_bytes_no_headers_separator():
    armored_key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----"

    with pytest.raises(ValueError, match="The key block has no armor headers separator"):
        get_armored_key_bytes(armored_key)
