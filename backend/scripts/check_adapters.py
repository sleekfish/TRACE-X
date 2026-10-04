"""Manual verification script for the forensic tool adapters.

Run with::

    python scripts/check_adapters.py

It prints the HONEST integration status of every adapter and exercises the
built-in parsers against a small, locally generated sample so that the
parsing pipeline can be verified without any external tool installed.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.adapters import (  # noqa: E402
    AutopsyAdapter,
    GenericAdapter,
    SiemAdapter,
    TsharkAdapter,
    VelociraptorAdapter,
    YaraAdapter,
    ZeekAdapter,
)


class _FakeEvidence:
    """Minimal stand-in for the Evidence ORM model."""

    def __init__(self, path: str, filename: str, evidence_type: str | None = None) -> None:
        self.storage_path = path
        self.original_filename = filename
        self.evidence_type = evidence_type
        self.sha256 = "0" * 64
        self.acquisition_source = ""


def _build_adapters():
    return [
        TsharkAdapter(),
        ZeekAdapter(),
        YaraAdapter(),
        VelociraptorAdapter(),
        SiemAdapter(),
        AutopsyAdapter(),
        GenericAdapter(),
    ]


def report_integrations() -> None:
    print("=" * 78)
    print("INTEGRATION STATUS (honest - no tool is faked)")
    print("=" * 78)
    for adapter in _build_adapters():
        info = adapter.integration_info()
        print(
            f"{info.name:<24} installed={str(info.installed):<5} "
            f"configured={str(info.configured):<5} status={info.status}"
        )
        print(f"{'':<24} detail: {info.detail}")
        print(f"{'':<24} available()={adapter.is_available()}  version={info.version}")


def exercise_generic_parser() -> None:
    print()
    print("=" * 78)
    print("REAL PARSING CHECK (built-in parser, no external tool)")
    print("=" * 78)
    tmp = Path(tempfile.mkdtemp(prefix="tracex_check_"))

    json_path = tmp / "siem_events.json"
    json_path.write_text(
        json.dumps(
            {
                "events": [
                    {
                        "timestamp": "2024-03-01T10:00:00Z",
                        "message": "Failed authentication for user jdoe",
                        "source": "siem",
                        "src_ip": "10.0.0.5",
                    },
                    {
                        "timestamp": "2024-03-01T10:05:00Z",
                        "message": "DNS query for evil-c2.example.com",
                        "source": "siem",
                        "dns_query": "evil-c2.example.com",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    csv_path = tmp / "autopsy_timeline.csv"
    csv_path.write_text(
        "timestamp,description,source\n"
        "2024-03-01T09:00:00Z,File created /tmp/payload.exe,autopsy\n"
        "2024-03-01T09:10:00Z,USB device connected,autopsy\n",
        encoding="utf-8",
    )

    log_path = tmp / "auth.log"
    log_path.write_text(
        "2024-03-01T08:00:00Z sshd: Accepted password for admin from 10.0.0.9\n"
        "2024-03-01T08:01:00Z sshd: Failed password for root from 45.33.12.7\n",
        encoding="utf-8",
    )

    checks = [
        (GenericAdapter(), _FakeEvidence(str(json_path), "siem_events.json", "JSON")),
        (AutopsyAdapter(), _FakeEvidence(str(csv_path), "autopsy_timeline.csv", "CSV")),
        (GenericAdapter(), _FakeEvidence(str(log_path), "auth.log", "LOG")),
    ]

    for adapter, evidence in checks:
        result = adapter.analyze(evidence)
        print(
            f"\n[{adapter.name}] {evidence.original_filename}\n"
            f"  status={result.status} source={result.source} "
            f"records={len(result.records)} exit_code={result.exit_code}"
        )
        for record in result.records[:2]:
            print(
                f"    - type={record.get('event_type')} "
                f"ts={record.get('timestamp')} "
                f"desc={str(record.get('description'))[:70]}"
            )


def exercise_uninstalled_tools() -> None:
    print()
    print("=" * 78)
    print("UNINSTALLED TOOL BEHAVIOUR (must be UNAVAILABLE / NOT_INSTALLED)")
    print("=" * 78)
    tmp = Path(tempfile.mkdtemp(prefix="tracex_check_"))
    dummy = tmp / "capture.pcap"
    dummy.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 32)
    evidence = _FakeEvidence(str(dummy), "capture.pcap", "PCAP")

    for adapter in (TsharkAdapter(), ZeekAdapter(), YaraAdapter()):
        result = adapter.analyze(evidence)
        print(
            f"{adapter.name:<14} status={result.status:<12} "
            f"message={result.error_message}"
        )

    velo = VelociraptorAdapter().analyze(evidence)
    print(f"{'velociraptor':<14} status={velo.status:<12} message={velo.error_message}")


def main() -> int:
    report_integrations()
    exercise_generic_parser()
    exercise_uninstalled_tools()
    print()
    print("Adapter verification complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())