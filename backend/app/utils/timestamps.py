"""Timestamp helpers.

All timestamps are stored as *naive UTC* to behave identically on SQLite and
PostgreSQL.  Serialisation to the API appends a ``Z`` suffix.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Optional


def utcnow() -> dt.datetime:
    """Return the current UTC time as a naive datetime."""
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def to_iso_z(value: Optional[dt.datetime]) -> Optional[str]:
    """Serialise a datetime to an ISO-8601 string with a ``Z`` suffix."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.isoformat(timespec="seconds") + "Z"
    return (
        value.astimezone(dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def parse_timestamp(value: Any) -> Optional[dt.datetime]:
    """Best-effort parsing of timestamps from heterogeneous tool output."""
    if value is None or value == "":
        return None
    if isinstance(value, dt.datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    if isinstance(value, (int, float)):
        try:
            return dt.datetime.fromtimestamp(
                float(value), tz=dt.timezone.utc
            ).replace(tzinfo=None)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        # Numeric epoch (seconds or milliseconds).
        if text.replace(".", "", 1).isdigit():
            try:
                number = float(text)
                if number > 1e12:  # milliseconds
                    number /= 1000.0
                return dt.datetime.fromtimestamp(
                    number, tz=dt.timezone.utc
                ).replace(tzinfo=None)
            except (OverflowError, OSError, ValueError):
                return None
        normalised = text.replace("Z", "+00:00")
        try:
            parsed = dt.datetime.fromisoformat(normalised)
            return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
        except ValueError:
            pass
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
            "%b %d %H:%M:%S",
        ):
            try:
                parsed = dt.datetime.strptime(text, fmt)
                return parsed.replace(tzinfo=None)
            except ValueError:
                continue
    return None