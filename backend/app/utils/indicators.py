"""Indicator extraction and normalisation.

Given a blob of text (tool output, log line, event description), extract and
canonicalise indicators of compromise:

IPv4, IPv6, DOMAIN, URL, HASH (md5/sha1/sha256), EMAIL, HOSTNAME, FILE, USER.

Domain normalisation is case-insensitive; URLs preserve path but normalise the
scheme + host.  The canonical representation is what gets stored as
``normalized_value``.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Set, Tuple
from urllib.parse import urlsplit, urlunsplit

# --- Indicator type constants ------------------------------------------------
IP = "IP"
DOMAIN = "DOMAIN"
URL = "URL"
HASH = "HASH"
EMAIL = "EMAIL"
HOSTNAME = "HOSTNAME"
FILE = "FILE"
USER = "USER"
PROCESS = "PROCESS"
CERTIFICATE = "CERTIFICATE"
OTHER = "OTHER"

SUPPORTED_TYPES = [
    IP,
    DOMAIN,
    URL,
    HASH,
    EMAIL,
    FILE,
    PROCESS,
    USER,
    HOSTNAME,
    CERTIFICATE,
    OTHER,
]

# --- Regular expressions -----------------------------------------------------
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{0,4}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+(?:[A-Za-z]{2,24})\b"
)
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\)\]]+", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[A-Fa-f0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[A-Fa-f0-9]{40}\b")
_MD5_RE = re.compile(r"\b[A-Fa-f0-9]{32}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_FILE_RE = re.compile(r"\b[\w\-. ]+\.(?:exe|dll|sys|bin|sh|bat|ps1|js|jar|doc|docx|xls|xlsx|pdf|zip|rar|7z|txt|log|php|py)\b", re.IGNORECASE)

# Common file extensions that are clearly NOT domains (avoid false positives).
_FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bin", "sh", "bat", "ps1", "js", "jar", "doc", "docx",
    "xls", "xlsx", "pdf", "zip", "rar", "7z", "txt", "log", "php", "py", "pcap",
    "pcapng", "json", "csv", "xml", "html", "htm", "ini", "cfg", "conf", "yara",
    "yar", "dat", "tmp", "bak", "md", "yml", "yaml", "evtx", "cap",
}

# TLD-like tokens that are almost certainly file extensions in log contexts.
_IGNORE_DOMAIN_SUFFIXES = _FILE_EXTENSIONS

# Private / special-use ranges are still recorded but flagged for context.


def normalize_domain(value: str) -> str:
    return value.strip().strip(".").lower()


def normalize_url(value: str) -> str:
    value = value.strip()
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if not parts.scheme or not parts.netloc:
        return value
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    path = parts.path or ""
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def normalize_hash(value: str) -> str:
    return value.strip().lower()


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_link_local
        or ip.is_unspecified
    )


def _is_probable_domain(value: str) -> bool:
    parts = value.lower().split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1]
    if tld in _IGNORE_DOMAIN_SUFFIXES:
        return False
    if not tld.isalpha() or len(tld) < 2:
        return False
    if value.replace(".", "").isdigit():
        return False
    return True


def canonical_indicator(indicator_type: str, value: str) -> str:
    """Return the canonical ``normalized_value`` for an indicator."""
    if indicator_type == DOMAIN:
        return normalize_domain(value)
    if indicator_type == URL:
        return normalize_url(value)
    if indicator_type == HASH:
        return normalize_hash(value)
    if indicator_type == EMAIL:
        return value.strip().lower()
    return value.strip()


def extract_indicators(text: str, context: str = "") -> List[Dict[str, str]]:
    """Extract de-duplicated indicators from free text.

    Returns a list of dicts with keys ``type``, ``value`` and ``normalized``.
    Ordering: URLs first (so their host/domain are not double-counted as bare
    domains unless they appear independently), then hashes, IPs, emails,
    domains, files.
    """
    if not text:
        return []

    found: Dict[Tuple[str, str], Dict[str, str]] = {}
    url_hosts: Set[str] = set()

    def add(indicator_type: str, raw: str) -> None:
        raw = raw.strip().strip("\"'<>()[]{},")
        if not raw:
            return
        normalized = canonical_indicator(indicator_type, raw)
        key = (indicator_type, normalized)
        if key not in found:
            found[key] = {"type": indicator_type, "value": raw, "normalized": normalized}

    # --- URLs (highest priority) --------------------------------------------
    for match in _URL_RE.findall(text):
        add(URL, match)
        try:
            host = urlsplit(match).hostname or ""
        except ValueError:
            host = ""
        if host:
            url_hosts.add(host.lower())
            if is_valid_ip(host):
                add(IP, host)
            elif _is_probable_domain(host):
                add(DOMAIN, host)

    # --- Hashes (longest first so sha256 is not split) ----------------------
    for regex in (_SHA256_RE, _SHA1_RE, _MD5_RE):
        for match in regex.findall(text):
            add(HASH, match)

    # --- Emails -------------------------------------------------------------
    email_tokens: Set[str] = set()
    for match in _EMAIL_RE.findall(text):
        add(EMAIL, match)
        email_tokens.add(match.lower())

    # --- IPs ----------------------------------------------------------------
    for match in _IPV4_RE.findall(text):
        add(IP, match)
    for match in _IPV6_RE.findall(text):
        if "::" in match or match.count(":") >= 2:
            add(IP, match)

    # --- Domains (skip ones subsumed by URLs / emails) ----------------------
    for match in _DOMAIN_RE.findall(text):
        lowered = match.lower()
        if lowered in url_hosts:
            continue
        if any(lowered in email for email in email_tokens):
            continue
        if _is_probable_domain(match):
            add(DOMAIN, match)

    # --- File names ---------------------------------------------------------
    for match in _FILE_RE.findall(text):
        add(FILE, match.strip())

    return list(found.values())