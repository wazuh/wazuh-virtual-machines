import base64
import binascii
import hashlib

WAZUH_GPG_KEY_URL = "https://packages.wazuh.com/key/GPG-KEY-WAZUH"
# Fingerprints of the Wazuh keys trusted to sign the packages. Extending the expiry date of a
# key keeps its fingerprint, so only a new key needs a new entry here.
WAZUH_GPG_KEY_FINGERPRINTS = ["0DCFCA5547B19D2A6099506096B3EE5F29111145"]

ARMOR_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
PUBLIC_KEY_PACKET_TAG = 6


def get_armored_key_bytes(armored_key: str) -> bytes:
    """
    Decodes an ASCII-armored OpenPGP public key into its binary form.

    Args:
        armored_key (str): The ASCII-armored key.

    Returns:
        bytes: The binary key.

    Raises:
        ValueError: If the text does not hold exactly one public key block or the block cannot be decoded.
    """
    # rpm --import would also take a second key block appended to the file.
    if armored_key.count(ARMOR_BEGIN) != 1:
        raise ValueError("The key file must hold a single public key block")

    lines = [line.strip() for line in armored_key.split(ARMOR_BEGIN)[1].splitlines()[1:]]
    if "" not in lines:
        raise ValueError("The key block has no armor headers separator")

    # The data starts after the armor headers and ends at the checksum or the END line.
    data = []
    for line in lines[lines.index("") + 1 :]:
        if line.startswith(("=", "-----")):
            break
        data.append(line)

    try:
        return base64.b64decode("".join(data), validate=True)
    except binascii.Error as err:
        raise ValueError("The key block is not valid base64") from err


def get_gpg_key_fingerprint(armored_key: str) -> str:
    """
    Returns the fingerprint of the primary key of an ASCII-armored OpenPGP public key.

    The fingerprint of a v4 key is the SHA-1 of 0x99, the two-byte length of the public key
    packet body and the body itself (RFC 4880, section 12.2).

    Args:
        armored_key (str): The ASCII-armored key.

    Returns:
        str: The fingerprint in upper case hexadecimal.

    Raises:
        ValueError: If the key cannot be parsed or does not hold exactly one primary key.
    """
    key = get_armored_key_bytes(armored_key)
    fingerprints = []
    position = 0

    while position < len(key):
        tag_byte = key[position]
        if not tag_byte & 0x80:
            raise ValueError("The key holds an invalid OpenPGP packet")

        if tag_byte & 0x40:
            tag = tag_byte & 0x3F
            first_length_byte = key[position + 1]
            if first_length_byte < 192:
                header_length, body_length = 2, first_length_byte
            elif first_length_byte < 224:
                header_length, body_length = 3, ((first_length_byte - 192) << 8) + key[position + 2] + 192
            elif first_length_byte == 255:
                header_length, body_length = 6, int.from_bytes(key[position + 2 : position + 6], "big")
            else:
                raise ValueError("The key holds an OpenPGP packet with a partial length")
        else:
            tag = (tag_byte >> 2) & 0x0F
            length_type = tag_byte & 0x03
            if length_type == 3:
                raise ValueError("The key holds an OpenPGP packet with an indeterminate length")
            length_size = 1 << length_type
            header_length = 1 + length_size
            body_length = int.from_bytes(key[position + 1 : position + header_length], "big")

        body = key[position + header_length : position + header_length + body_length]
        if len(body) != body_length:
            raise ValueError("The key holds a truncated OpenPGP packet")

        if tag == PUBLIC_KEY_PACKET_TAG:
            if body[0] != 4:
                raise ValueError("The key is not a v4 OpenPGP key")
            fingerprints.append(hashlib.sha1(b"\x99" + body_length.to_bytes(2, "big") + body).hexdigest().upper())

        position += header_length + body_length

    if len(fingerprints) != 1:
        raise ValueError(f"The key must hold a single primary key, found {len(fingerprints)}")

    return fingerprints[0]
