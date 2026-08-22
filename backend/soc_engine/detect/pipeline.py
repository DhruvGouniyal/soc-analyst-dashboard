"""
Detection pipeline: neutral records in, validated wire events out.

The same instance serves both the historical backfill and the live tail, so
history and live traffic are interpreted identically. Nothing here reads the
wall clock — every decision uses the record's own timestamp, which is what lets
the backfill reproduce the brute-force and port-scan events that the last 24
hours actually contained.
"""

from __future__ import annotations

from ..config import Settings, settings as default_settings
from ..ids import stable_event_id
from ..models import WireEvent
from ..parsers.records import AuthKind, AuthRecord, UfwBlockRecord
from .bruteforce import BruteForceConfig, SlidingWindowCorrelator
from .portscan import PortScanConfig, PortScanCorrelator
from .sessions import InvalidUserPrecursor, SessionTracker

SSH_PORT = 22

# MITRE technique per detection, mirroring src/config/eventTypes.ts.
MITRE = {
    "ssh_brute_force": "T1110",
    "ssh_failed_auth": "T1110",
    "successful_login": "T1078",
    "suspicious_login": "T1078",
    "port_scan": "T1046",
    "privilege_escalation": "T1068",
    "new_connection": "T1071",
}


class DetectionPipeline:
    def __init__(self, config: Settings | None = None) -> None:
        self.settings = config or default_settings
        self.brute_force = SlidingWindowCorrelator(
            BruteForceConfig(
                window_seconds=self.settings.brute_force_window_seconds,
                threshold=self.settings.brute_force_threshold,
                cooldown_seconds=self.settings.brute_force_cooldown_seconds,
            )
        )
        self.port_scan = PortScanCorrelator(
            PortScanConfig(
                window_seconds=self.settings.port_scan_window_seconds,
                threshold=self.settings.port_scan_threshold,
                cooldown_seconds=self.settings.port_scan_cooldown_seconds,
            )
        )
        self.sessions = SessionTracker()

    # ------------------------------------------------------------------ auth
    def feed_auth(self, record: AuthRecord) -> list[WireEvent]:
        """Processes one auth.log record. May emit zero, one, or two events."""
        handler = {
            AuthKind.FAILED_PASSWORD: self._on_failed_password,
            AuthKind.FAILED_INVALID_USER: self._on_failed_invalid_user,
            AuthKind.INVALID_USER: self._on_invalid_user,
            AuthKind.MAX_AUTH_EXCEEDED: self._on_max_auth,
            AuthKind.ACCEPTED: self._on_accepted,
            AuthKind.SESSION_ABORTED: self._on_session_aborted,
            AuthKind.SUDO_BAD_PASSWORD: self._on_sudo_bad_password,
            AuthKind.SUDO_NOT_SUDOER: self._on_sudo_not_sudoer,
            AuthKind.SU_FAILED: self._on_su_failed,
        }.get(record.kind)
        return handler(record) if handler else []

    def _on_failed_password(self, record: AuthRecord) -> list[WireEvent]:
        # The Failed line supersedes any Invalid-user precursor for this pid.
        self.sessions.resolve(record.pid)
        events = [
            self._auth_event(
                record,
                event_type="ssh_failed_auth",
                severity="medium",
                description=f'Failed password for "{record.user}"',
                detail=(
                    f"A single SSH password failure from {record.src_ip}. Benign in isolation; "
                    "correlate against this source for a developing brute-force pattern."
                ),
                confidence=78,
            )
        ]
        events.extend(self._maybe_brute_force(record, weight=1))
        return events

    def _on_failed_invalid_user(self, record: AuthRecord) -> list[WireEvent]:
        self.sessions.resolve(record.pid)
        events = [
            self._auth_event(
                record,
                event_type="suspicious_login",
                severity="medium",
                description=f'Invalid SSH credentials for "{record.user}"',
                detail=(
                    f'Authentication attempted against account "{record.user}", which does not '
                    "exist on this host. Indicates credential guessing rather than a mistyped "
                    "password."
                ),
                confidence=84,
            )
        ]
        events.extend(self._maybe_brute_force(record, weight=1))
        return events

    def _on_invalid_user(self, record: AuthRecord) -> list[WireEvent]:
        # Held, not emitted — see sessions.py for why.
        if record.src_ip:
            self.sessions.remember(
                record.pid,
                InvalidUserPrecursor(
                    ts_ms=record.ts_ms,
                    user=record.user or "",
                    src_ip=record.src_ip,
                    src_port=record.src_port,
                    raw_line=record.raw_line,
                ),
            )
        return []

    def _on_session_aborted(self, record: AuthRecord) -> list[WireEvent]:
        precursor = self.sessions.take_if_unresolved(record.pid, record.ts_ms)
        if precursor is None:
            return []
        # The client gave up before submitting a password; report the attempt
        # that would otherwise be lost.
        synthetic = AuthRecord(
            ts_ms=precursor.ts_ms,
            kind=AuthKind.FAILED_INVALID_USER,
            raw_line=precursor.raw_line,
            user=precursor.user,
            src_ip=precursor.src_ip,
            src_port=precursor.src_port,
            pid=record.pid,
        )
        events = [
            self._auth_event(
                synthetic,
                event_type="suspicious_login",
                severity="medium",
                description=f'Invalid SSH user "{precursor.user or "(empty)"}" probed',
                detail=(
                    "Connection closed before a password was submitted. Consistent with "
                    "automated username enumeration."
                ),
                confidence=72,
            )
        ]
        events.extend(self._maybe_brute_force(synthetic, weight=1))
        return events

    def _on_max_auth(self, record: AuthRecord) -> list[WireEvent]:
        # sshd only logs this after MaxAuthTries (default 6) guesses, so it
        # stands for several attempts, not one.
        events = [
            self._auth_event(
                record,
                event_type="ssh_failed_auth",
                severity="high",
                description=f'Maximum authentication attempts exceeded for "{record.user}"',
                detail=(
                    "sshd terminated the connection after repeated failures within a single "
                    "session. Counted as multiple attempts by the correlator."
                ),
                confidence=90,
            )
        ]
        events.extend(self._maybe_brute_force(record, weight=3))
        return events

    def _on_accepted(self, record: AuthRecord) -> list[WireEvent]:
        ts_seconds = record.ts_ms / 1000.0
        prior_failures = (
            self.brute_force.recent_failures(
                record.src_ip,
                ts_seconds,
                self.settings.login_escalation_lookback_seconds,
            )
            if record.src_ip
            else 0
        )
        # A login that succeeds right after a run of failures is the single most
        # valuable correlation auth.log offers: it is what a successful brute
        # force looks like.
        escalated = prior_failures >= self.settings.login_escalation_min_failures

        event = self._auth_event(
            record,
            event_type="successful_login",
            severity="high" if escalated else "low",
            description=(
                f'Login succeeded for "{record.user}" after {prior_failures} recent failures'
                if escalated
                else f'Accepted {record.method or "password"} for "{record.user}"'
            ),
            detail=(
                f"Session established from {record.src_ip}. {prior_failures} failed attempts were "
                "seen from this source beforehand — treat as a probable credential compromise and "
                "verify the session."
                if escalated
                else f"Session established from {record.src_ip}. Verify the source is expected."
            ),
            confidence=88 if escalated else 65,
        )
        if record.src_ip:
            self.brute_force.reset(record.src_ip)
        return [event]

    def _on_sudo_bad_password(self, record: AuthRecord) -> list[WireEvent]:
        count = record.attempt_count or 1
        return [
            self._local_event(
                record,
                event_type="privilege_escalation",
                severity="high",
                description=f'{count} failed sudo attempts by "{record.user}"',
                detail=(
                    f'User "{record.user}" failed sudo authentication {count} times. Review whether '
                    "this account should hold elevated rights and whether the session is legitimate."
                ),
                confidence=82,
            )
        ]

    def _on_sudo_not_sudoer(self, record: AuthRecord) -> list[WireEvent]:
        return [
            self._local_event(
                record,
                event_type="privilege_escalation",
                severity="critical",
                description=f'Non-sudoer "{record.user}" attempted privilege escalation',
                detail=(
                    f'User "{record.user}" invoked sudo without being in the sudoers file. On a '
                    "host with no shared accounts this is a strong hands-on-keyboard indicator."
                ),
                confidence=93,
            )
        ]

    def _on_su_failed(self, record: AuthRecord) -> list[WireEvent]:
        return [
            self._local_event(
                record,
                event_type="privilege_escalation",
                severity="high",
                description=f'Failed su to "{record.target_user}" by "{record.user}"',
                detail=(
                    f'User "{record.user}" attempted to switch to "{record.target_user}" and failed '
                    "authentication."
                ),
                confidence=85,
            )
        ]

    def _maybe_brute_force(self, record: AuthRecord, weight: int) -> list[WireEvent]:
        if not record.src_ip:
            return []
        burst = self.brute_force.record_failure(
            record.src_ip, record.ts_ms / 1000.0, record.user, weight=weight
        )
        if burst is None:
            return []

        targets = ", ".join(f"{user} ({count})" for user, count in burst.top_users) or "unknown"
        return [
            WireEvent(
                id=stable_event_id(
                    record.ts_ms, "ssh_brute_force", burst.ip, extra=str(burst.attempts)
                ),
                timestamp=record.ts_ms,
                severity="critical",
                eventType="ssh_brute_force",
                sourceIp=burst.ip,
                sourcePort=record.src_port,
                destinationIp=self.settings.victim_ip,
                destinationPort=SSH_PORT,
                protocol="SSH",
                host=self.settings.victim_host_id,
                description=(
                    f"{burst.attempts} failed SSH authentications in {int(burst.span_seconds)}s"
                ),
                detail=(
                    f"Targeted accounts: {targets}. Attempt rate exceeds human interactive speed, "
                    "indicating an automated tool. Block the source and confirm no session "
                    "succeeded."
                ),
                status="new",
                mitreTechnique=MITRE["ssh_brute_force"],
                confidence=min(99.0, 80.0 + burst.attempts),
                logSource="auth.log",
                rawLog=record.raw_line,
            )
        ]

    # ------------------------------------------------------------------- ufw
    def feed_ufw(self, record: UfwBlockRecord) -> list[WireEvent]:
        """Port-scan detection. Individual blocked packets are not events —
        only a qualifying sweep is."""
        scan = self.port_scan.record_block(
            record.src_ip, record.dst_port, record.ts_ms / 1000.0
        )
        if scan is None:
            return []

        ports = ", ".join(str(p) for p in scan.sample_ports)
        return [
            WireEvent(
                id=stable_event_id(
                    record.ts_ms, "port_scan", scan.ip, extra=str(scan.distinct_ports)
                ),
                timestamp=record.ts_ms,
                severity="high",
                eventType="port_scan",
                sourceIp=scan.ip,
                sourcePort=record.src_port,
                destinationIp=record.dst_ip,
                destinationPort=None,
                protocol=record.protocol if record.protocol in {"TCP", "UDP", "ICMP"} else "TCP",
                host=self.settings.victim_host_id,
                description=f"{scan.distinct_ports} ports scanned",
                detail=(
                    f"{scan.total_probes} blocked packets across {scan.distinct_ports} distinct "
                    f"ports in {int(scan.span_seconds)}s (including {ports}). Consistent with a "
                    "service enumeration sweep; commonly precedes targeted exploitation."
                ),
                status="new",
                mitreTechnique=MITRE["port_scan"],
                confidence=min(97.0, 70.0 + scan.distinct_ports),
                logSource="syslog",
                rawLog=record.raw_line,
            )
        ]

    # ----------------------------------------------------------------- utils
    def sweep(self, now_seconds: float) -> None:
        self.brute_force.sweep(now_seconds)
        self.port_scan.sweep(now_seconds)

    def _auth_event(
        self,
        record: AuthRecord,
        *,
        event_type: str,
        severity: str,
        description: str,
        detail: str,
        confidence: float,
    ) -> WireEvent:
        """Builds a network-sourced auth event (attacker → victim:22)."""
        return WireEvent(
            id=stable_event_id(
                record.ts_ms,
                event_type,
                record.src_ip or "0.0.0.0",
                record.src_port,
                record.pid,
                record.user,
            ),
            timestamp=record.ts_ms,
            severity=severity,  # type: ignore[arg-type]
            eventType=event_type,  # type: ignore[arg-type]
            sourceIp=record.src_ip or "0.0.0.0",
            sourcePort=record.src_port,
            destinationIp=self.settings.victim_ip,
            destinationPort=SSH_PORT,
            protocol="SSH",
            host=self.settings.victim_host_id,
            description=description,
            detail=detail,
            status="new",
            mitreTechnique=MITRE.get(event_type),
            confidence=confidence,
            logSource="auth.log",
            rawLog=record.raw_line,
        )

    def _local_event(
        self,
        record: AuthRecord,
        *,
        event_type: str,
        severity: str,
        description: str,
        detail: str,
        confidence: float,
    ) -> WireEvent:
        """
        Builds a host-local event (sudo/su). Source and destination are both the
        victim, since the activity did not cross the network — reporting an
        attacker IP here would be a fabrication.
        """
        return WireEvent(
            id=stable_event_id(
                record.ts_ms, event_type, self.settings.victim_ip, None, record.pid, record.user
            ),
            timestamp=record.ts_ms,
            severity=severity,  # type: ignore[arg-type]
            eventType=event_type,  # type: ignore[arg-type]
            sourceIp=self.settings.victim_ip,
            sourcePort=None,
            destinationIp=self.settings.victim_ip,
            destinationPort=None,
            protocol="TCP",
            host=self.settings.victim_host_id,
            description=description,
            detail=detail,
            status="new",
            mitreTechnique=MITRE.get(event_type),
            confidence=confidence,
            logSource="auth.log",
            rawLog=record.raw_line,
        )
