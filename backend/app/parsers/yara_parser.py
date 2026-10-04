"""Parser for YARA scan output.

Supports the default text format (``rule_name file_path``) and the namespace
variant (``namespace:rule_name file_path``).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from app.parsers.base import BaseParser, EventType

_MATCH_RE = re.compile(
    r"^(?:(?P<namespace>[A-Za-z0-9_]+):)?(?P<rule>[A-Za-z0-9_]+)\s+"
    r"(?P<file>.+?)(?:\s+\[(?P<tags>[^\]]*)\])?$"
)


class YaraParser(BaseParser):
    name = "yara"

    def parse(self, content: str, **kwargs: Any) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        for line in (content or "").splitlines():
            line = line.strip()
            if not line or line.startswith("error:") or line.startswith("warning:"):
                continue
            if line.startswith("0x") or line.startswith("$"):
                continue
            match = _MATCH_RE.match(line)
            if not match:
                continue
            rule = match.group("rule")
            namespace = match.group("namespace") or "default"
            target = match.group("file").strip()
            tags = [t for t in (match.group("tags") or "").split(",") if t.strip()]
            records.append(
                {
                    "timestamp": None,
                    "event_type": EventType.YARA_MATCH,
                    "description": f"YARA rule '{rule}' matched {target}",
                    "raw_reference": f"yara:{namespace}:{rule}",
                    "confidence": 0.7,
                    "metadata": {
                        "rule": rule,
                        "namespace": namespace,
                        "matched_file": target,
                        "tags": tags,
                    },
                }
            )
        return records