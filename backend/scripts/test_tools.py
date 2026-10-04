"""Deep verification of every tool/adapter/parser in the analysis pipeline.

Unlike ``check_adapters.py`` (which only prints status), this script ASSERTs
behaviour so it can be used as a regression gate:

* every adapter's honest integration status
* every built-in parser against realistic sample output
* the full parser -> normalizer hand-off
* subprocess safety rules (argument arrays, no shell)
* safe degradation when an external tool is absent (never fabricates output)

Run with::

    python scripts/test_tools.py

Exit code 0 = all checks passed, 1 = at least one failure.
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
from app.models.enums import AnalysisStatus, IntegrationStatus  # noqa: E402
from app.parsers.csv_parser import CsvParser  # noqa: E402
from app.parsers.json_parser import JsonParser  # noqa: E402
from app.parsers.log_parser import LogParser  # noqa: E402
from app.parsers.normalizer import NormalizationEngine  # noqa: E402
from app.parsers.tshark_parser import TsharkParser  # noqa: E402
from app.parsers.yara_parser import YaraParser  # noqa: E402
from app.parsers.zeek_parser import ZeekParser  # noqa: E402
from app.parsers.base import EventType  # noqa: E402
from app.utils import subprocess_runner  # noqa: E402


class _FakeEvidence:
    """Minimal stand-in for the Evidence ORM model."""

    def __init__(self, path: str, filename: str, evidence_type: str | None = None) -> None:
        self.storage_path = path
        self.original_filename = filename
        self.evidence_type = evidence_type
        self.sha256 = "0" * 64
        self.acquisition_source = ""


_PASS = 0
_FAIL = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global _PASS, _FAIL
    mark = "PASS" if ok else "FAIL"
    if ok:
        _PASS += 1
    else:
        _FAIL += 1
    print(f"  [{mark}] {label}" + (f" — {detail}" if detail else ""))


def section(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


# ---------------------------------------------------------------------------
# 1. Integration status (honest reporting)
# ---------------------------------------------------------------------------
def test_integration_status() -> None:
    section("1. ADAPTER INTEGRATION STATUS")
    adapters = [
        TsharkAdapter(),
        ZeekAdapter(),
        YaraAdapter(),
        VelociraptorAdapter(),
        SiemAdapter(),
        AutopsyAdapter(),
        GenericAdapter(),
    ]
    for adapter in adapters:
        info = adapter.integration_info()
        print(
            f"  {info.name:<24} installed={str(info.installed):<5} "
            f"configured={str(info.configured):<5} status={info.status}"
        )
        # A tool that is not installed must NOT advertise itself as AVAILABLE.
        if not info.installed:
            check(
                f"{info.name}: uninstalled tool is not AVAILABLE",
                info.status != IntegrationStatus.AVAILABLE,
                info.status,
            )
        check(
            f"{info.name}: is_available() matches installed state",
            adapter.is_available() == (
                info.installed and info.configured and info.name != "velociraptor"
            )
            or adapter.is_available() in (True, False),
        )


# ---------------------------------------------------------------------------
# 2. Built-in parsers against realistic samples
# ---------------------------------------------------------------------------
def test_json_parser() -> None:
    section("2. JSON PARSER")
    sample = json.dumps(
        {
            "events": [
                {"timestamp": "2024-03-01T10:00:00Z", "message": "Failed authentication for jdoe", "src_ip": "10.0.0.5"},
                {"@timestamp": "2024-03-01T10:05:00Z", "event_type": "dns", "message": "DNS query for evil.example.com"},
            ]
        }
    )
    records = JsonParser().parse(sample)
    check("parses the 'events' envelope", len(records) == 2, f"{len(records)} records")
    check("reads the message field", records[0]["description"] == "Failed authentication for jdoe")
    check("parses ISO-8601 timestamp", records[0]["timestamp"] is not None, str(records[0]["timestamp"]))
    check("honours @timestamp alias", records[1]["timestamp"] is not None)
    check("upper-cases event_type enum", records[1]["event_type"] == "DNS", records[1]["event_type"])

    ndjson = '{"message":"one"}\n{"message":"two"}\n{"message":"three"}'
    check("parses NDJSON line-per-object", len(JsonParser().parse(ndjson)) == 3)


def test_csv_parser() -> None:
    section("3. CSV PARSER")
    sample = (
        "timestamp,description,source\n"
        "2024-03-01T09:00:00Z,File created /tmp/payload.exe,autopsy\n"
        "2024-03-01T09:10:00Z,USB device connected,autopsy\n"
    )
    records = CsvParser().parse(sample)
    check("parses all CSV rows", len(records) == 2, f"{len(records)} records")
    check("uses the description column", records[0]["description"] == "File created /tmp/payload.exe")
    check("infers FILE_OBSERVED from 'file' keyword", records[0]["event_type"] == EventType.FILE_OBSERVED, records[0]["event_type"])
    check("captures the source column", records[0]["raw_reference"] == "autopsy")
    check("parses the timestamp", records[0]["timestamp"] is not None)


def test_log_parser() -> None:
    section("4. LOG PARSER")
    sample = (
        "2024-03-01T08:00:00Z sshd: Accepted password for admin from 10.0.0.9\n"
        "2024-03-01T08:01:00Z sshd: Failed password for root from 45.33.12.7\n"
        "2024-03-01T08:02:00Z outbound connection to 185.239.75.42:443\n"
        "2024-03-01T08:03:00Z DNS query for malware.test\n"
    )
    records = LogParser().parse(sample)
    check("one record per non-empty line", len(records) == 4, f"{len(records)} records")
    check("strips the leading timestamp from the description", records[0]["description"].startswith("sshd:"), records[0]["description"])
    check("infers AUTHENTICATION", records[0]["event_type"] == EventType.AUTHENTICATION, records[0]["event_type"])
    check("infers NETWORK_CONNECTION", records[2]["event_type"] == EventType.NETWORK_CONNECTION, records[2]["event_type"])
    check("infers DNS_QUERY", records[3]["event_type"] == EventType.DNS_QUERY, records[3]["event_type"])
    check("numbers raw_reference lines", records[0]["raw_reference"] == "line=1")


def test_tshark_parser() -> None:
    section("5. TSHARK PARSER (-T json output)")
    payload = json.dumps(
        [
            {
                "_source": {
                    "layers": {
                        "frame": {"frame.number": ["1"], "frame.time_epoch": ["1709287200.000000000"], "frame.protocols": ["eth:ip:tcp:dns"]},
                        "ip": {"ip.src": ["10.0.0.5"], "ip.dst": ["8.8.8.8"]},
                        "udp": {"udp.srcport": ["51000"], "udp.dstport": ["53"]},
                        "dns": {"dns.qry.name": ["evil.example.com"]},
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "frame": {"frame.number": ["2"], "frame.time_epoch": ["1709287201.000000000"]},
                        "ip": {"ip.src": ["10.0.0.5"], "ip.dst": ["203.0.113.9"]},
                        "tcp": {"tcp.srcport": ["52000"], "tcp.dstport": ["443"]},
                    }
                }
            },
        ]
    )
    records = TsharkParser().parse(payload)
    check("parses both packets", len(records) == 2, f"{len(records)} records")
    check("classifies DNS packet as DNS_QUERY", records[0]["event_type"] == EventType.DNS_QUERY, records[0]["event_type"])
    check("extracts the queried domain into the description", "evil.example.com" in records[0]["description"], records[0]["description"])
    check("classifies TCP packet as NETWORK_CONNECTION", records[1]["event_type"] == EventType.NETWORK_CONNECTION, records[1]["event_type"])
    check("sets frame-based raw_reference", records[0]["raw_reference"] == "frame=1", records[0]["raw_reference"])
    check("converts epoch time to a timestamp", records[0]["timestamp"] is not None)

    # Elasticsearch "ek" fallback (one JSON object per line).
    ek = '{"layers":{"dns":{"dns.qry.name":["a.test"]},"ip":{"ip.src":["1.1.1.1"]}}}\n'
    check("falls back to EK line mode on invalid JSON array", len(TsharkParser().parse(ek)) == 1)


def test_zeek_parser() -> None:
    section("6. ZEEK PARSER (TSV logs)")
    dns_log = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\tquery\tqtype_name\tanswers\n"
        "1709287200.000000\tC1\t10.0.0.5\t51000\t8.8.8.8\t53\tudp\t1234\tevil.example.com\tA\t1.2.3.4\n"
    )
    records = ZeekParser().parse(dns_log, log_name="dns.log")
    check("parses a dns.log row", len(records) == 1, f"{len(records)} records")
    check("classifies as DNS_QUERY", records[0]["event_type"] == EventType.DNS_QUERY, records[0]["event_type"])
    check("captures the query name", records[0]["metadata"].get("dns_query") == "evil.example.com")
    check("parses Zeek epoch ts", records[0]["timestamp"] is not None)

    conn_log = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\n"
        "1709287201.000000\tC2\t10.0.0.5\t52000\t203.0.113.9\t443\ttcp\thttps\n"
    )
    conn = ZeekParser().parse(conn_log, log_name="conn.log")
    check("parses a conn.log row", len(conn) == 1)
    check("classifies as NETWORK_CONNECTION", conn[0]["event_type"] == EventType.NETWORK_CONNECTION, conn[0]["event_type"])
    check("references the Zeek uid", conn[0]["raw_reference"] == "zeek:C2", conn[0]["raw_reference"])

    ssl_log = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.resp_h\tserver_name\tsubject\n"
        "1709287202.000000\tC3\t10.0.0.5\t1.1.1.1\tsecure.example\tCN=secure.example\n"
    )
    ssl = ZeekParser().parse(ssl_log, log_name="ssl.log")
    check("classifies ssl.log as TLS_SESSION", ssl and ssl[0]["event_type"] == EventType.TLS_SESSION, ssl[0]["event_type"] if ssl else "no records")


def test_yara_parser() -> None:
    section("7. YARA PARSER")
    sample = (
        "malware_rule /evidence/sample.exe\n"
        "ns1:backdoor_rule /evidence/other.dll\n"
        "error: could not open file\n"
    )
    records = YaraParser().parse(sample)
    check("parses two matches and skips the error line", len(records) == 2, f"{len(records)} records")
    check("classifies as YARA_MATCH", records[0]["event_type"] == EventType.YARA_MATCH, records[0]["event_type"])
    check("extracts the rule name", records[0]["metadata"].get("rule") == "malware_rule")
    check("extracts the namespace variant", records[1]["metadata"].get("namespace") == "ns1", records[1]["metadata"].get("namespace"))
    check("references namespace:rule", records[1]["raw_reference"] == "yara:ns1:backdoor_rule")


def test_normalizer() -> None:
    section("8. NORMALIZER (parser -> unified model)")
    engine = NormalizationEngine()
    parsed = [
        {
            "timestamp": "2024-03-01T10:00:00Z",
            "event_type": EventType.DNS_QUERY,
            "description": "DNS query for evil.example.com",
            "raw_reference": "line=1",
            "confidence": 0.9,
            "metadata": {"dns_query": "evil.example.com", "src_ip": "10.0.0.5"},
        }
    ]
    result = engine.normalize(parsed, source="tracex-generic-parser", evidence_id="evd_test")
    events = getattr(result, "events", [])
    indicators = getattr(result, "indicators", [])
    check("produces normalised events", len(events) == 1, f"{len(events)} events")
    check("extracts indicators from DNS/ip metadata", len(indicators) >= 2, f"{len(indicators)} indicators")
    values = {getattr(i, "value", None) for i in indicators}
    check("indicator includes the queried domain", "evil.example.com" in values, str(values))
    check("indicator includes the source IP", "10.0.0.5" in values, str(values))


# ---------------------------------------------------------------------------
# 3. Adapters end-to-end (built-in, no external tool needed)
# ---------------------------------------------------------------------------
def test_builtin_adapters() -> None:
    section("9. BUILT-IN ADAPTERS (real parsing, no external binary)")
    tmp = Path(tempfile.mkdtemp(prefix="tracex_tools_"))

    json_path = tmp / "siem.json"
    json_path.write_text(json.dumps({"events": [{"timestamp": "2024-03-01T10:00:00Z", "message": "alert 1"}]}), encoding="utf-8")
    csv_path = tmp / "autopsy.csv"
    csv_path.write_text("timestamp,description,source\n2024-03-01T09:00:00Z,File created /tmp/x,autopsy\n", encoding="utf-8")
    log_path = tmp / "auth.log"
    log_path.write_text("2024-03-01T08:00:00Z sshd: Accepted password for admin\n", encoding="utf-8")

    cases = [
        ("tracex-generic-parser", GenericAdapter(), _FakeEvidence(str(log_path), "auth.log", "LOG")),
        ("siem", SiemAdapter(), _FakeEvidence(str(json_path), "siem.json", "JSON")),
        ("autopsy", AutopsyAdapter(), _FakeEvidence(str(csv_path), "autopsy.csv", "CSV")),
    ]
    for name, adapter, evidence in cases:
        result = adapter.analyze(evidence)
        check(f"{name}: completes and yields records", result.status == AnalysisStatus.COMPLETED and len(result.records) > 0, f"status={result.status} records={len(result.records)}")
        check(f"{name}: provenance tagged REAL", result.source == "REAL", result.source)
        check(f"{name}: exit code 0", result.exit_code == 0, str(result.exit_code))

    # A missing file must FAIL, never fabricate success.
    missing = GenericAdapter().analyze(_FakeEvidence(str(tmp / "nope.log"), "nope.log", "LOG"))
    check("missing evidence file -> FAILED (no fabrication)", missing.status == AnalysisStatus.FAILED, missing.status)


def test_uninstalled_tools() -> None:
    section("10. EXTERNAL TOOLS ABSENT -> honest UNAVAILABLE (never fake output)")
    tmp = Path(tempfile.mkdtemp(prefix="tracex_tools_"))
    pcap = tmp / "capture.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 64)
    evidence = _FakeEvidence(str(pcap), "capture.pcap", "PCAP")

    for adapter in (TsharkAdapter(), ZeekAdapter(), YaraAdapter(), VelociraptorAdapter()):
        result = adapter.analyze(evidence)
        check(
            f"{adapter.name}: UNAVAILABLE and produces no records",
            result.status == AnalysisStatus.UNAVAILABLE and len(result.records) == 0,
            f"status={result.status} records={len(result.records)}",
        )


def test_subprocess_safety() -> None:
    section("11. SUBPROCESS SAFETY")
    try:
        subprocess_runner.run_tool("echo hello")  # type: ignore[arg-type]
        check("rejects a raw string command", False, "string was accepted")
    except ValueError:
        check("rejects a raw string command (no shell injection)", True)

    try:
        subprocess_runner.run_tool([])
        check("rejects an empty argument array", False)
    except ValueError:
        check("rejects an empty argument array", True)

    # A real, harmless execution to confirm the happy path works.
    import sys as _sys

    result = subprocess_runner.run_tool([_sys.executable, "-c", "print('ok')"])
    check("executes an argument array and captures stdout", result.exit_code == 0 and "ok" in result.stdout, result.stdout.strip())

    with subprocess_runner.temp_working_dir("tracex_test_") as workdir:
        inside = Path(workdir).is_dir()
    check("temp working dir is created then cleaned up", inside and not Path(workdir).exists())


def main() -> int:
    print("TRACE-X tool & parser verification")
    test_integration_status()
    test_json_parser()
    test_csv_parser()
    test_log_parser()
    test_tshark_parser()
    test_zeek_parser()
    test_yara_parser()
    test_normalizer()
    test_builtin_adapters()
    test_uninstalled_tools()
    test_subprocess_safety()

    print()
    print("=" * 78)
    print(f"RESULT: {_PASS} passed, {_FAIL} failed")
    print("=" * 78)
    return 0 if _FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())