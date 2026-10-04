"""Evidence hashing utilities.

Evidence files are hashed in *streaming* chunks so that arbitrarily large
artefacts can be processed without loading them fully into memory.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO, Dict

DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB


def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_of_stream(stream: BinaryIO, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Compute the SHA-256 of a binary stream, reading in fixed-size chunks."""
    digest = hashlib.sha256()
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def hash_file(path: str | Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Dict[str, str]:
    """Compute common hashes for a file on disk (streaming)."""
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }