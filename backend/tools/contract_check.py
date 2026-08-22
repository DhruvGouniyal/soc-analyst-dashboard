"""
Wire-contract validator.

Replays a log file through the real pipeline and asserts every emitted event
against the dashboard's expectations — independently of the Pydantic models, so
this still catches a mistake if someone loosens a model.

The dashboard's normalizeEvent never rejects bad data; it substitutes a
plausible-looking default. A seconds-valued timestamp, a string port, or a
snake_case key all produce a dashboard that renders perfectly and shows the
wrong thing. This asserts the things that would otherwise fail silently.

Usage:
    python tools/contract_check.py                          # uses the test fixture
    python tools/contract_check.py /var/log/auth.log        # a real log
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from soc_engine.config import Settings  # noqa: E402
from soc_engine.detect.pipeline import DetectionPipeline  # noqa: E402
from soc_engine.parsers.sshd import parse_auth_line  # noqa: E402
from soc_engine.parsers.ufw import parse_ufw_line  # noqa: E402

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_STATUSES = {"new", "investigating", "blocked", "resolved"}
VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "SSH", "DNS"}
VALID_LOG_SOURCES = {"auth.log", "syslog", "audit.log", "suricata", "netflow", "process"}
VALID_EVENT_TYPES = {
    "ssh_brute_force", "ssh_failed_auth", "successful_login", "port_scan",
    "suspicious_login", "web_attack", "suspicious_process", "privilege_escalation",
    "data_exfiltration", "new_connection", "malware_signature",
}
VALID_MITRE = {"T1110", "T1046", "T1059", "T1078", "T1190", "T1068", "T1048", "T1071", "T1204"}

# The client accepts snake_case for exactly three keys and silently ignores
# every other snake_case field. Emitting camelCase throughout removes the risk.
EXPECTED_KEYS = {
    "id", "timestamp", "severity", "eventType", "sourceIp", "sourcePort",
    "destinationIp", "destinationPort", "protocol", "host", "description",
    "detail", "status", "mitreTechnique", "confidence", "logSource", "rawLog",
}

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def validate_event(event: dict, host_ids: set[str], index: int) -> None:
    where = f"event[{index}] ({event.get('eventType', '?')})"

    check(isinstance(event.get("id"), str) and event["id"], f"{where}: id must be a non-empty str")

    ts = event.get("timestamp")
    check(isinstance(ts, int) and not isinstance(ts, bool), f"{where}: timestamp must be an int")
    check(
        isinstance(ts, int) and ts > 1_000_000_000_000,
        f"{where}: timestamp {ts} looks like SECONDS — the dashboard would render 1970",
    )

    check(event.get("severity") in VALID_SEVERITIES, f"{where}: bad severity {event.get('severity')!r}")
    check(event.get("eventType") in VALID_EVENT_TYPES, f"{where}: bad eventType")
    check(event.get("status") in VALID_STATUSES, f"{where}: bad status {event.get('status')!r}")
    check(event.get("protocol") in VALID_PROTOCOLS, f"{where}: bad protocol {event.get('protocol')!r}")
    check(event.get("logSource") in VALID_LOG_SOURCES, f"{where}: bad logSource")

    for port_key in ("sourcePort", "destinationPort"):
        port = event.get(port_key)
        check(
            port is None or (isinstance(port, int) and not isinstance(port, bool)),
            f"{where}: {port_key}={port!r} must be int or None — a string becomes null",
        )

    confidence = event.get("confidence")
    check(
        isinstance(confidence, (int, float)) and 0 <= confidence <= 100,
        f"{where}: confidence {confidence!r} must be a number 0-100",
    )

    mitre = event.get("mitreTechnique")
    check(
        mitre is None or mitre in VALID_MITRE,
        f"{where}: mitreTechnique {mitre!r} has no entry in the dashboard catalog",
    )

    check(
        event.get("host") in host_ids,
        f"{where}: host {event.get('host')!r} does not match a published host id {host_ids}",
    )

    for key in ("sourceIp", "destinationIp", "description"):
        check(isinstance(event.get(key), str) and event[key], f"{where}: {key} must be a non-empty str")

    unexpected = set(event) - EXPECTED_KEYS
    check(not unexpected, f"{where}: unexpected keys {unexpected}")
    snake = {k for k in event if "_" in k}
    check(not snake, f"{where}: snake_case keys {snake} would be silently ignored")


def main() -> int:
    settings = Settings()
    pipeline = DetectionPipeline(settings)
    host_ids = {settings.victim_host_id}

    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    auth_path = Path(sys.argv[1]) if len(sys.argv) > 1 else fixtures / "auth.log.sample"
    kern_path = fixtures / "kern.log.sample" if len(sys.argv) <= 1 else None

    events = []
    for line in auth_path.read_text(encoding="utf-8", errors="replace").splitlines():
        record = parse_auth_line(line)
        if record:
            events.extend(pipeline.feed_auth(record))

    if kern_path and kern_path.is_file():
        for line in kern_path.read_text(encoding="utf-8", errors="replace").splitlines():
            record = parse_ufw_line(line)
            if record:
                events.extend(pipeline.feed_ufw(record))

    print(f"Replayed {auth_path} -> {len(events)} events\n")

    by_type: dict[str, int] = {}
    for index, event in enumerate(events):
        payload = event.model_dump(mode="json")
        by_type[payload["eventType"]] = by_type.get(payload["eventType"], 0) + 1
        validate_event(payload, host_ids, index)

    for event_type, count in sorted(by_type.items(), key=lambda kv: -kv[1]):
        print(f"  {event_type:<22} {count}")

    if events:
        print("\nSample payload:")
        sample = events[-1].model_dump(mode="json")
        for key in sorted(sample):
            print(f"  {key:<16} {sample[key]!r}")

    print()
    if failures:
        print(f"CONTRACT VIOLATIONS ({len(failures)}):")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"CONTRACT OK — {len(events)} events validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
