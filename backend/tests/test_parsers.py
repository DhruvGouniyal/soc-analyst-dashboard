"""
Parser tests.

The negative assertions matter as much as the positive ones: counting a
pam_unix line or emitting on both halves of the invalid-user pair are the two
mistakes that would quietly wreck the detection counts.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from soc_engine.parsers.records import AuthKind
from soc_engine.parsers.sshd import parse_auth_line
from soc_engine.parsers.syslog_ts import infer_year, parse_syslog_time, to_epoch_ms
from soc_engine.parsers.ufw import parse_ufw_line

TZ = timezone(timedelta(hours=5, minutes=30))
NOW = datetime(2026, 8, 22, 12, 0, 0, tzinfo=TZ)


def test_failed_password():
    line = "Aug 22 11:41:02 ubuntu-victim sshd[24811]: Failed password for root from 192.168.56.106 port 51236 ssh2"
    record = parse_auth_line(line, NOW)
    assert record is not None
    assert record.kind is AuthKind.FAILED_PASSWORD
    assert record.user == "root"
    assert record.src_ip == "192.168.56.106"
    assert record.src_port == 51236
    assert record.pid == 24811


def test_failed_invalid_user_is_distinct_from_plain_failure():
    line = "Aug 22 11:41:05 ubuntu-victim sshd[24812]: Failed password for invalid user admin from 192.168.56.106 port 51240 ssh2"
    record = parse_auth_line(line, NOW)
    assert record is not None
    assert record.kind is AuthKind.FAILED_INVALID_USER
    assert record.user == "admin"


def test_space_padded_single_digit_day():
    """`Aug  2` has TWO spaces — a naive split() drops a field."""
    line = "Aug  2 09:00:01 ubuntu-victim sshd[19001]: Failed password for ubuntu from 10.10.10.24 port 40001 ssh2"
    record = parse_auth_line(line, NOW)
    assert record is not None
    assert record.src_ip == "10.10.10.24"
    assert datetime.fromtimestamp(record.ts_ms / 1000, TZ).day == 2


def test_ipv6_source():
    line = "Aug 22 11:44:00 ubuntu-victim sshd[24850]: Failed password for postgres from 2001:db8::dead:beef port 40222 ssh2"
    record = parse_auth_line(line, NOW)
    assert record is not None
    assert record.src_ip == "2001:db8::dead:beef"


def test_empty_username_invalid_user():
    """sshd logs an empty username when the client sends one; \\S+ would miss it."""
    line = "Aug 22 11:43:01 ubuntu-victim sshd[24840]: Invalid user  from 185.220.101.47 port 60001"
    record = parse_auth_line(line, NOW)
    assert record is not None
    assert record.kind is AuthKind.INVALID_USER
    assert record.user == ""
    assert record.src_ip == "185.220.101.47"


@pytest.mark.parametrize(
    "line",
    [
        "Aug 22 11:40:58 ubuntu-victim sshd[24810]: pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=192.168.56.106  user=root",
        "Aug 22 11:41:12 ubuntu-victim sshd[24814]: PAM 5 more authentication failures; logname= uid=0 rhost=192.168.56.106",
        "Aug 22 11:49:00 ubuntu-victim sshd[25010]: Server listening on 0.0.0.0 port 22.",
        "Aug 22 11:49:30 ubuntu-victim sshd[25011]: Received disconnect from 192.168.56.106 port 51300:11: Bye Bye [preauth]",
        "Aug 22 11:50:00 ubuntu-victim sshd[25012]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
    ],
)
def test_noise_lines_are_ignored(line):
    """Counting these would multiply the failure count and misfire the correlator."""
    assert parse_auth_line(line, NOW) is None


def test_max_auth_exceeded():
    line = "Aug 22 11:45:00 ubuntu-victim sshd[24860]: error: maximum authentication attempts exceeded for root from 192.168.56.107 port 41000 ssh2 [preauth]"
    record = parse_auth_line(line, NOW)
    assert record is not None
    assert record.kind is AuthKind.MAX_AUTH_EXCEEDED
    assert record.src_ip == "192.168.56.107"


def test_accepted_login():
    line = "Aug 22 11:42:10 ubuntu-victim sshd[24830]: Accepted password for ubuntu from 192.168.56.106 port 51290 ssh2"
    record = parse_auth_line(line, NOW)
    assert record is not None
    assert record.kind is AuthKind.ACCEPTED
    assert record.user == "ubuntu"


def test_accepted_publickey_with_key_fingerprint():
    line = "Aug 22 11:42:11 ubuntu-victim sshd[24831]: Accepted publickey for ubuntu from 192.168.56.106 port 51291 ssh2: RSA SHA256:abc123def456"
    record = parse_auth_line(line, NOW)
    assert record is not None
    assert record.kind is AuthKind.ACCEPTED
    assert record.method == "publickey"


def test_sudo_and_su():
    bad_pw = parse_auth_line(
        "Aug 22 11:46:00 ubuntu-victim sudo:   deploy : 3 incorrect password attempts ; TTY=pts/1 ; USER=root ; COMMAND=/usr/bin/id",
        NOW,
    )
    assert bad_pw is not None and bad_pw.kind is AuthKind.SUDO_BAD_PASSWORD
    assert bad_pw.attempt_count == 3
    assert bad_pw.user == "deploy"

    not_sudoer = parse_auth_line(
        "Aug 22 11:47:00 ubuntu-victim sudo:   guest : user NOT in sudoers ; TTY=pts/2 ; USER=root ; COMMAND=/bin/bash",
        NOW,
    )
    assert not_sudoer is not None and not_sudoer.kind is AuthKind.SUDO_NOT_SUDOER

    su_failed = parse_auth_line(
        "Aug 22 11:48:00 ubuntu-victim su[25000]: FAILED SU (to root) deploy on pts/3", NOW
    )
    assert su_failed is not None and su_failed.kind is AuthKind.SU_FAILED
    assert su_failed.target_user == "root"


# ------------------------------------------------------------------ timestamps
def test_year_inference_uses_current_year_for_past_dates():
    resolved = infer_year(8, 22, 11, 41, 2, NOW)
    assert resolved.year == 2026


def test_december_to_january_rollover():
    """On Jan 1st, a Dec 31 line belongs to LAST year."""
    new_year = datetime(2027, 1, 1, 0, 5, 0, tzinfo=TZ)
    resolved = infer_year(12, 31, 23, 59, 58, new_year)
    assert resolved.year == 2026


def test_slight_future_skew_is_tolerated():
    """A victim clock a few seconds ahead must not push the line back a year."""
    reference = datetime(2026, 8, 22, 11, 59, 59, tzinfo=TZ)
    resolved = infer_year(8, 22, 12, 0, 30, reference)
    assert resolved.year == 2026


def test_impossible_date_returns_none_instead_of_raising():
    """
    Feb 29 with no adjacent leap year cannot be resolved. A corrupt or forged
    line must be skipped, never crash the tailer — auth.log is a file an
    attacker can write into.
    """
    reference = datetime(2027, 3, 1, 0, 0, 0, tzinfo=TZ)
    assert infer_year(2, 29, 12, 0, 0, reference) is None


def test_leap_day_resolves_when_a_leap_year_is_adjacent():
    reference = datetime(2025, 3, 1, 0, 0, 0, tzinfo=TZ)
    resolved = infer_year(2, 29, 12, 0, 0, reference)
    assert resolved is not None and resolved.year == 2024


def test_impossible_date_line_is_skipped_not_fatal():
    line = "Feb 29 12:00:00 ubuntu-victim sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    reference = datetime(2027, 3, 1, 0, 0, 0, tzinfo=TZ)
    assert parse_auth_line(line, reference) is None


def test_rfc3339_timestamp():
    moment = parse_syslog_time("2026-08-22T11:41:02.123456+05:30", NOW)
    assert moment is not None
    assert moment.year == 2026 and moment.minute == 41


def test_epoch_ms_is_milliseconds_not_seconds():
    """The single most damaging contract mistake — guard it explicitly."""
    ts = to_epoch_ms(NOW)
    assert ts > 1_000_000_000_000
    assert len(str(ts)) == 13


# ------------------------------------------------------------------------ ufw
def test_ufw_block_line():
    line = (
        "Aug 22 12:00:00 ubuntu-victim kernel: [12345.678901] [UFW BLOCK] IN=enp0s3 OUT= "
        "MAC=08:00:27:aa:bb:cc SRC=192.168.56.106 DST=192.168.56.105 LEN=44 TTL=42 ID=11001 "
        "PROTO=TCP SPT=53412 DPT=21 WINDOW=1024 RES=0x00 SYN URGP=0"
    )
    record = parse_ufw_line(line, NOW)
    assert record is not None
    assert record.src_ip == "192.168.56.106"
    assert record.dst_ip == "192.168.56.105"
    assert record.dst_port == 21
    assert record.protocol == "TCP"


def test_ufw_icmp_has_no_ports():
    line = (
        "Aug 22 12:00:04 ubuntu-victim kernel: [12345.688001] [UFW BLOCK] IN=enp0s3 OUT= "
        "SRC=192.168.56.106 DST=192.168.56.105 LEN=92 TTL=64 ID=11011 PROTO=ICMP TYPE=8 CODE=0"
    )
    record = parse_ufw_line(line, NOW)
    assert record is not None
    assert record.dst_port is None
    assert record.protocol == "ICMP"


def test_non_block_kernel_line_ignored():
    line = "Aug 22 12:00:05 ubuntu-victim kernel: [12345.7] usb 1-1: new high-speed USB device"
    assert parse_ufw_line(line, NOW) is None
