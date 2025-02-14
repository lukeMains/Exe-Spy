"""Utilities for analysing binary files"""

import hashlib
from typing import Set
import io


def strings(data: bytes, min_length=10) -> Set[str]:
    """Return a strings of ASCII strings found in the provided bytes.
    :param data: A binary file to find strings in
    """
    strings = set()
    with io.BytesIO(data) as f:
        current_string = b""
        byte = f.read(1)

        while byte:
            if b" " <= byte <= b"~":
                current_string += byte
            else:
                if len(current_string) >= min_length:
                    strings.add(
                        (
                            current_string.decode("ascii"),
                            f.tell() - len(current_string) - 1,
                        )
                    )
                current_string = b""
            byte = f.read(1)

        if len(current_string) >= min_length:
            strings.add(
                (current_string.decode("ascii"), f.tell() - len(current_string))
            )

    return strings


def calculate_sha256(data: bytes) -> str:
    """Generate a SHA256 hash of the provided bytes
    :param data: Bytes used to calculate sha256 digest"""
    sha256 = hashlib.sha256()
    # Calculate the hashes while only looping through the file once
    with io.BytesIO(data) as f:
        # Read the file in chunks of 4096 bytes
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256.update(byte_block)
    return sha256.hexdigest()
