"""
hash_types.py -- Hash signature definitions and identification logic.
"""

import re
import base64
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class HashMatch:
    name: str
    description: str
    hashcat_mode: Optional[int]
    john_format: str
    confidence: str  # "high", "medium", "low"

    @property
    def hashcat_flag(self) -> str:
        if self.hashcat_mode is not None:
            return f"-m {self.hashcat_mode}"
        return "N/A"

    @property
    def john_flag(self) -> str:
        return f"--format={self.john_format}"


# Ordered so more-specific patterns come before overlapping generic ones.
HASH_SIGNATURES = [
    {
        "name": "bcrypt",
        "pattern": r"^\$2[aby]\$\d{2}\$.{53}$",
        "hashcat_mode": 3200,
        "john_format": "bcrypt",
        "description": "bcrypt (Blowfish-based) -- extremely slow to crack by design",
        "confidence": "high",
    },
    {
        "name": "MySQL5+ / SHA1",
        "pattern": r"^\*[0-9a-fA-F]{40}$",
        "hashcat_mode": 300,
        "john_format": "mysql-sha1",
        "description": "MySQL 4.1+ (SHA1-based, prefixed with *)",
        "confidence": "high",
    },
    {
        "name": "PostgreSQL MD5",
        "pattern": r"^md5[0-9a-fA-F]{32}$",
        "hashcat_mode": None,
        "john_format": "dynamic_1034",
        "description": "PostgreSQL MD5 -- md5(password + username); needs username to crack",
        "confidence": "high",
    },
    {
        "name": "SHA-512",
        "pattern": r"^[0-9a-fA-F]{128}$",
        "hashcat_mode": 1700,
        "john_format": "raw-sha512",
        "description": "SHA-512 (128 hex characters)",
        "confidence": "high",
    },
    {
        "name": "SHA-256",
        "pattern": r"^[0-9a-fA-F]{64}$",
        "hashcat_mode": 1400,
        "john_format": "raw-sha256",
        "description": "SHA-256 (64 hex characters)",
        "confidence": "high",
    },
    {
        "name": "SHA-1",
        "pattern": r"^[0-9a-fA-F]{40}$",
        "hashcat_mode": 100,
        "john_format": "raw-sha1",
        "description": "SHA-1 (40 hex characters)",
        "confidence": "high",
    },
    # MD5 and NTLM are both 32 hex -- show both so the analyst can choose.
    {
        "name": "MD5",
        "pattern": r"^[0-9a-fA-F]{32}$",
        "hashcat_mode": 0,
        "john_format": "raw-md5",
        "description": "MD5 (32 hex characters)",
        "confidence": "medium",
    },
    {
        "name": "NTLM",
        "pattern": r"^[0-9a-fA-F]{32}$",
        "hashcat_mode": 1000,
        "john_format": "nt",
        "description": "NTLM / Windows NT Hash (also 32 hex -- context-dependent)",
        "confidence": "medium",
    },
    {
        "name": "MySQL 3.x (old)",
        "pattern": r"^[0-9a-fA-F]{16}$",
        "hashcat_mode": 200,
        "john_format": "mysql",
        "description": "MySQL 3.x old hash (16 hex characters)",
        "confidence": "high",
    },
]


def _is_base64(s: str) -> bool:
    if len(s) < 8:
        return False
    if not re.match(r'^[A-Za-z0-9+/]+=*$', s):
        return False
    if len(s) % 4 != 0:
        return False
    try:
        decoded = base64.b64decode(s)
        return len(decoded) > 0
    except Exception:
        return False


def identify_hash(hash_str: str) -> List[HashMatch]:
    """
    Return a list of HashMatch objects for all matching hash types.
    Multiple matches are possible (e.g. MD5 vs NTLM for 32-hex strings).
    """
    h = hash_str.strip()
    matches: List[HashMatch] = []

    for sig in HASH_SIGNATURES:
        if re.match(sig["pattern"], h, re.IGNORECASE):
            matches.append(HashMatch(
                name=sig["name"],
                description=sig["description"],
                hashcat_mode=sig["hashcat_mode"],
                john_format=sig["john_format"],
                confidence=sig["confidence"],
            ))

    # Only suggest Base64 if nothing else matched -- hex hashes are also valid
    # base64 chars, so we avoid false positives on MD5/NTLM/SHA-1 hashes.
    if not matches and _is_base64(h):
        matches.append(HashMatch(
            name="Base64",
            description="Base64-encoded data (not a hash -- decode first with: base64 -d)",
            hashcat_mode=None,
            john_format="N/A",
            confidence="low",
        ))

    return matches
