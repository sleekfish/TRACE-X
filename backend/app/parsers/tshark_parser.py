"""Parser for ``tshark -T json`` output."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from app.core.logging import get_logger
from app.parsers.base import BaseParser, EventType
from app.utils.timestamps import parse_timestamp

logger = get_logger(__name__)


def _flatten_layers(layers: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten tshark's nested ``layers`` dict into ``field -> value`` pairs."""
    flat: Dict[str, Any] = {}
    for key, value in layers.items():
        if isinstance(value, dict):
            nested = _flatten_layers(value)
            for nkey, nvalue in nested.items():
                flat[nkey] = nvalue
            flat.setdefault(key, value)
        else:
            flat[key] = value
    return flat


class TsharkParser(BaseParser):
    name = "tshark"

    def parse(self, content: str, **kwargs: Any) -> List[Dict[str, Any]]:
        content = (content or "").strip()
        if not content:
            return []
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            logger.warning("tshark output is not valid JSON; falling back to line mode")
            return self._parse_ek_lines(content)

        packets: List[Dict[str, Any]] = []
        if isinstance(payload, dict):
            payload = payload.get("packets", [payload])
        if not isinstance(payload, list):
            return []

        for packet in payload:
            layers: Dict[str, Any] = {}
            if isinstance(packet, dict):
                source = packet.get("_source", packet)
                if isinstance(source, dict) and "layers" in source:
                    layers = source["layers"] or {}
                elif isinstance(source, dict):
                    layers = source
            if not isinstance(layers, dict):
                continue
            flat = _flatten_layers(layers)
            record = self._record_from_fields(flat)
            if record:
                packets.append(record)
        return packets

    def _parse_ek_lines(self, content: str) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            layers = obj.get("layers", obj) if isinstance(obj, dict) else {}
            if isinstance(layers, dict):
                record = self._record_from_fields(_flatten_layers(layers))
                if record:
                    records.append(record)
        return records

    def _record_from_fields(self, flat: Dict[str, Any]) -> Dict[str, Any]:
        def get(key: str) -> str:
            return self._as_text(self._first(flat.get(key)))

        timestamp = parse_timestamp(
            self._first(flat.get("frame.time_epoch"))
            or self._first(flat.get("frame.time"))
        )

        src_ip = get("ip.src") or get("ipv6.src")
        dst_ip = get("ip.dst") or get("ipv6.dst")
        src_port = get("tcp.srcport") or get("udp.srcport")
        dst_port = get("tcp.dstport") or get("udp.dstport")
        protocol = get("frame.protocols") or get("ip.proto")
        dns_query = get("dns.qry.name")
        http_host = get("http.host")
        http_uri = get("http.request.uri")
        http_method = get("http.request.method")
        http_ua = get("http.user_agent")
        tls_sni = get("tls.handshake.extensions_server_name")
        frame_number = get("frame.number")

        metadata: Dict[str, Any] = {
            "frame_number": frame_number,
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
        }
        if dns_query:
            metadata["dns_query"] = dns_query
        if http_host:
            metadata["http_host"] = http_host
        if http_uri:
            metadata["http_uri"] = http_uri
        if http_method:
            metadata["http_method"] = http_method
        if http_ua:
            metadata["http_user_agent"] = http_ua
        if tls_sni:
            metadata["tls_server_name"] = tls_sni

        if dns_query:
            event_type = EventType.DNS_QUERY
            description = f"DNS query for {dns_query}"
            if src_ip:
                description += f" from {src_ip}"
        elif http_host or http_uri:
            event_type = EventType.HTTP_REQUEST
            target = http_host or ""
            if http_uri:
                target = f"{target}{http_uri}"
            description = f"HTTP {http_method or 'request'} to {target}".strip()
        elif tls_sni:
            event_type = EventType.TLS_SESSION
            description = f"TLS session with server name {tls_sni}"
        elif src_ip and dst_ip:
            event_type = EventType.NETWORK_CONNECTION
            description = f"Network connection {src_ip}"
            if src_port:
                description += f":{src_port}"
            description += f" -> {dst_ip}"
            if dst_port:
                description += f":{dst_port}"
        else:
            return {}

        return {
            "timestamp": timestamp,
            "event_type": event_type,
            "description": description,
            "raw_reference": f"frame={frame_number}" if frame_number else "tshark",
            "confidence": 0.9,
            "metadata": metadata,
        }