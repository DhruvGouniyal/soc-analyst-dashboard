"""
Detection-engine tests: correlation behaviour and the wire contract.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_engine.config import Settings
from soc_engine.detect.bruteforce import BruteForceConfig, SlidingWindowCorrelator
from soc_engine.detect.pipeline import DetectionPipeline
from soc_engine.detect.portscan import PortScanConfig, PortScanCorrelator
from soc_engine.parsers.sshd import parse_auth_line
from soc_engine.parsers.ufw import parse_ufw_line

TZ = timezone(timedelta(hours=5, minutes=30))
NOW = datetime(2026, 8, 22, 13, 0, 0, tzinfo=TZ)
FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------- brute force
def test_threshold_fires_once_then_cools_down():
    correlator = SlidingWindowCorrelator(
        BruteForceConfig(window_seconds=60, threshold=5, cooldown_seconds=300)
    )
    fired = [correlator.record_failure("1.2.3.4", float(t), "root") for t in range(10)]
    bursts = [b for b in fired if b is not None]
    # Exactly one alert for a ten-attempt burst — not six.
    assert len(bursts) == 1
    assert bursts[0].attempts == 5


def test_slow_attempts_never_fire():
    """One failure every 30s is a forgetful user, not an attack."""
    correlator = SlidingWindowCorrelator(BruteForceConfig(window_seconds=60, threshold=5))
    bursts = [correlator.record_failure("1.2.3.4", float(t * 30), "root") for t in range(10)]
    assert all(b is None for b in bursts)


def test_cooldown_expiry_allows_a_second_alert():
    correlator = SlidingWindowCorrelator(
        BruteForceConfig(window_seconds=60, threshold=5, cooldown_seconds=300)
    )
    first = [correlator.record_failure("1.2.3.4", float(t), "root") for t in range(6)]
    later = [correlator.record_failure("1.2.3.4", 400.0 + t, "root") for t in range(6)]
    assert sum(b is not None for b in first) == 1
    assert sum(b is not None for b in later) == 1


def test_sources_are_tracked_independently():
    correlator = SlidingWindowCorrelator(BruteForceConfig(window_seconds=60, threshold=5))
    for t in range(4):
        assert correlator.record_failure("1.1.1.1", float(t), "root") is None
        assert correlator.record_failure("2.2.2.2", float(t), "root") is None
    # 4 each — neither has crossed 5 on its own.
    assert correlator.record_failure("1.1.1.1", 5.0, "root") is not None


def test_weight_counts_multiple_attempts():
    """MaxAuthTries stands for several guesses, so it must weigh more than one."""
    correlator = SlidingWindowCorrelator(BruteForceConfig(window_seconds=60, threshold=5))
    assert correlator.record_failure("1.2.3.4", 0.0, "root", weight=3) is None
    assert correlator.record_failure("1.2.3.4", 1.0, "root", weight=3) is not None


def test_successful_login_resets_the_window():
    correlator = SlidingWindowCorrelator(BruteForceConfig(window_seconds=60, threshold=5))
    for t in range(4):
        correlator.record_failure("1.2.3.4", float(t), "root")
    correlator.reset("1.2.3.4")
    assert correlator.record_failure("1.2.3.4", 5.0, "root") is None


# ----------------------------------------------------------------- port scan
def test_distinct_ports_required():
    """Twenty hits on ONE port is a retry loop, not a sweep."""
    correlator = PortScanCorrelator(PortScanConfig(window_seconds=60, threshold=10))
    results = [correlator.record_block("1.2.3.4", 8080, float(t)) for t in range(20)]
    assert all(r is None for r in results)


def test_distinct_ports_fire_a_scan():
    correlator = PortScanCorrelator(PortScanConfig(window_seconds=60, threshold=10))
    results = [correlator.record_block("1.2.3.4", 1000 + port, float(port)) for port in range(12)]
    scans = [r for r in results if r is not None]
    assert len(scans) == 1
    assert scans[0].distinct_ports == 10


def test_portless_packets_are_not_counted():
    correlator = PortScanCorrelator(PortScanConfig(window_seconds=60, threshold=2))
    assert correlator.record_block("1.2.3.4", None, 0.0) is None


# ------------------------------------------------------------------ pipeline
def _pipeline() -> DetectionPipeline:
    return DetectionPipeline(Settings())


def test_invalid_user_pair_emits_exactly_one_event():
    """
    sshd logs 'Invalid user' AND 'Failed password for invalid user' for the same
    guess. Emitting on both would double every count in the dashboard.
    """
    pipeline = _pipeline()
    invalid = parse_auth_line(
        "Aug 22 11:41:05 ubuntu-victim sshd[24812]: Invalid user admin from 192.168.56.106 port 51240",
        NOW,
    )
    failed = parse_auth_line(
        "Aug 22 11:41:05 ubuntu-victim sshd[24812]: Failed password for invalid user admin from 192.168.56.106 port 51240 ssh2",
        NOW,
    )
    assert pipeline.feed_auth(invalid) == []
    events = pipeline.feed_auth(failed)
    assert len(events) == 1
    assert events[0].eventType == "suspicious_login"


def test_abandoned_invalid_user_is_still_reported():
    """When the client disconnects before a password, the attempt still counts."""
    pipeline = _pipeline()
    invalid = parse_auth_line(
        "Aug 22 11:43:01 ubuntu-victim sshd[24840]: Invalid user bob from 185.220.101.47 port 60001",
        NOW,
    )
    closed = parse_auth_line(
        "Aug 22 11:43:03 ubuntu-victim sshd[24840]: Connection closed by invalid user bob 185.220.101.47 port 60001 [preauth]",
        NOW,
    )
    pipeline.feed_auth(invalid)
    events = pipeline.feed_auth(closed)
    assert len(events) == 1
    assert events[0].eventType == "suspicious_login"


def test_login_after_failures_is_escalated_to_high():
    pipeline = _pipeline()
    for second in range(4):
        line = f"Aug 22 11:41:0{second} ubuntu-victim sshd[2481{second}]: Failed password for ubuntu from 192.168.56.106 port 5123{second} ssh2"
        pipeline.feed_auth(parse_auth_line(line, NOW))

    accepted = parse_auth_line(
        "Aug 22 11:41:20 ubuntu-victim sshd[24830]: Accepted password for ubuntu from 192.168.56.106 port 51290 ssh2",
        NOW,
    )
    events = pipeline.feed_auth(accepted)
    assert len(events) == 1
    assert events[0].eventType == "successful_login"
    assert events[0].severity == "high"


def test_clean_login_stays_low():
    pipeline = _pipeline()
    accepted = parse_auth_line(
        "Aug 22 11:42:10 ubuntu-victim sshd[24830]: Accepted password for ubuntu from 10.0.0.9 port 51290 ssh2",
        NOW,
    )
    events = pipeline.feed_auth(accepted)
    assert events[0].severity == "low"


def test_sudo_failures_produce_privilege_escalation():
    pipeline = _pipeline()
    events = pipeline.feed_auth(
        parse_auth_line(
            "Aug 22 11:47:00 ubuntu-victim sudo:   guest : user NOT in sudoers ; TTY=pts/2 ; USER=root ; COMMAND=/bin/bash",
            NOW,
        )
    )
    assert events[0].eventType == "privilege_escalation"
    assert events[0].severity == "critical"
    assert events[0].mitreTechnique == "T1068"


def test_backfill_uses_log_time_not_wall_clock():
    """
    Historical failures spread across hours must NOT collapse into one window.
    If the correlator ever reached for time.time(), this would fire.
    """
    pipeline = _pipeline()
    events = []
    for hour in range(6):
        line = f"Aug 22 0{hour}:00:00 ubuntu-victim sshd[240{hour}0]: Failed password for root from 192.168.56.106 port 5120{hour} ssh2"
        events.extend(pipeline.feed_auth(parse_auth_line(line, NOW)))
    assert not any(e.eventType == "ssh_brute_force" for e in events)


def test_fixture_replay_produces_expected_mix():
    pipeline = _pipeline()
    emitted = []
    for line in (FIXTURES / "auth.log.sample").read_text(encoding="utf-8").splitlines():
        record = parse_auth_line(line, NOW)
        if record:
            emitted.extend(pipeline.feed_auth(record))

    kinds = [e.eventType for e in emitted]
    assert "ssh_failed_auth" in kinds
    assert "suspicious_login" in kinds
    assert "successful_login" in kinds
    assert "privilege_escalation" in kinds
    assert "ssh_brute_force" in kinds
    # Nothing without a real data source may appear.
    for forbidden in ("web_attack", "malware_signature", "suspicious_process", "data_exfiltration"):
        assert forbidden not in kinds


def test_ufw_fixture_produces_one_port_scan():
    pipeline = _pipeline()
    emitted = []
    for line in (FIXTURES / "kern.log.sample").read_text(encoding="utf-8").splitlines():
        record = parse_ufw_line(line, NOW)
        if record:
            emitted.extend(pipeline.feed_ufw(record))

    scans = [e for e in emitted if e.eventType == "port_scan"]
    assert len(scans) == 1
    assert scans[0].severity == "high"
    assert scans[0].sourceIp == "192.168.56.106"
    # The 10.10.10.24 rows all hit port 8080 — a retry loop, not a sweep.
    assert all(s.sourceIp != "10.10.10.24" for s in scans)


def test_ids_are_stable_across_runs():
    """Re-derived backfill events must keep their ids, or dedupe fails."""
    line = "Aug 22 11:41:02 ubuntu-victim sshd[24811]: Failed password for root from 192.168.56.106 port 51236 ssh2"
    first = _pipeline().feed_auth(parse_auth_line(line, NOW))[0]
    second = _pipeline().feed_auth(parse_auth_line(line, NOW))[0]
    assert first.id == second.id
    assert isinstance(first.id, str) and first.id
