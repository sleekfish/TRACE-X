"""Parser for Zeek TSV logs (conn.log, dns.log, http.log, ssl.log, files.log)."""

from __future__ import annotations

from typing import Any, Dict, List

from app.parsers.base import BaseParser, EventType
from app.utils.timestamps import parse_timestamp

_UNSET = {"-", "(empty)", ""}


class ZeekParser(BaseParser):
    name = "zeek"

    def parse(self, content: str, **kwargs: Any) -> List[Dict[str, Any]]:
        separator = "\t"
        fields: List[str] = []
        records: List[Dict[str, Any]] = []
        path_hint = kwargs.get("log_name", "")

        for line in (content or "").splitlines():
            if not line:
                continue
            if line.startswith("#separator"):
                raw = line.split(" ", 1)[1] if " " in line else "\\x09"
                separator = raw.encode().decode("unicode_escape")
                continue
            if line.startswith("#fields"):
                fields = line.split(separator)[1:]
                continue
            if line.startswith("#"):
                continue
            if not fields:
                continue
            values = line.split(separator)
            row = {}
            for index, name in enumerate(fields):
                value = values[index] if index < len(values) else ""
                row[name] = "" if value in _UNSET else value
            record = self._record_from_row(row, path_hint)
            if record:
                records.append(record)
        return records

    def _record_from_row(self, row: Dict[str, str], path_hint: str) -> Dict[str, Any]:
        ts = parse_timestamp(row.get("ts"))
        uid = row.get("uid", "")
        orig_h = row.get("id.orig_h", "")
        resp_h = row.get("id.resp_h", "")
        orig_p = row.get("id.orig_p", "")
        resp_p = row.get("id.resp_p", "")

        metadata: Dict[str, Any] = {
            "uid": uid,
            "src_ip": orig_h,
            "dst_ip": resp_h,
            "src_port": orig_p,
            "dst_port": resp_p,
            "log_type": path_hint or "zeek",
        }

        if row.get("query") or "dns" in path_hint:
            query = row.get("query", "")
            qtype = row.get("qtype_name", "")
            description = f"DNS query for {query}"
            if qtype:
                description += f" ({qtype})"
            metadata["dns_query"] = query
            metadata["answers"] = row.get("answers", "")
            return self._make(ts, EventType.DNS_QUERY, description, uid, metadata, 0.9)

        if row.get("host") or row.get("uri") or "http" in path_hint:
            host = row.get("host", "")
            uri = row.get("uri", "")
            method = row.get("method", "")
            description = f"HTTP {method} {host}{uri}".strip()
            metadata.update({"http_host": host, "http_uri": uri, "http_method": method})
            if row.get("user_agent"):
                metadata["http_user_agent"] = row["user_agent"]
            return self._make(ts, EventType.HTTP_REQUEST, description, uid, metadata, 0.9)

        if row.get("server_name") or "ssl" in path_hint:
            sni = row.get("server_name", "")
            description = f"TLS session with server name {sni}".strip()
            metadata["tls_server_name"] = sni
            if row.get("subject"):
                metadata["certificate_subject"] = row["subject"]
            if row.get("issuer"):
                metadata["certificate_issuer"] = row["issuer"]
            return self._make(ts, EventType.TLS_SESSION, description, uid, metadata, 0.85)

        if "files" in path_hint or row.get("filename") or row.get("mime_type"):
            filename = row.get("filename", "") or row.get("mime_type", "")
            description = f"File observed: {filename}".strip()
            for key in ("md5", "sha1", "sha256"):
                if row.get(key):
                    metadata[key] = row[key]
            metadata["mime_type"] = row.get("mime_type", "")
            metadata["filename"] = row.get("filename", "")
            return self._make(ts, EventType.FILE_OBSERVED, description, uid, metadata, 0.85)

        if orig_h or resp_h:
            proto = row.get("proto", "")
            description = f"Network connection {orig_h}:{orig_p} -> {resp_h}:{resp_p} ({proto})"
            metadata["proto"] = proto
            metadata["service"] = row.get("service", "")
            return self._make(ts, EventType.NETWORK_CONNECTION, description, uid, metadata, 0.85)

        return {}

    @staticmethod
    def _make(ts, event_type, description, uid, metadata, confidence) -> Dict[str, Any]:
        return {
            "timestamp": ts,
            "event_type": event_type,
            "description": description.strip(),
            "raw_reference": f"zeek:{uid}" if uid else "zeek",
            "confidence": confidence,
            "metadata": metadata,
        }