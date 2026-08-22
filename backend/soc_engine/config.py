"""
Runtime configuration, read once from the environment.

Plain ``os.environ`` rather than pydantic-settings: this service already has a
small dependency list and every value here is a scalar. Defaults are tuned for
the lab topology described in the project README.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_str(key: str, default: str) -> str:
    value = os.environ.get(key, "").strip()
    return value or default


def _env_int(key: str, default: int) -> int:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(key: str, default: float) -> float:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # --- Identity -----------------------------------------------------------
    # MUST match HOST_IDS.victim in src/data/topology.ts, or events join to no
    # host and the header's "Ubuntu Victim: ONLINE" indicator never turns green.
    victim_host_id: str = field(default_factory=lambda: _env_str("SOC_VICTIM_HOST_ID", "ubuntu-victim"))
    # MUST match VICTIM_IP in src/data/topology.ts. computeTopSources excludes
    # this exact string, so a mismatch makes the victim rank as its own attacker.
    victim_ip: str = field(default_factory=lambda: _env_str("SOC_VICTIM_IP", "192.168.56.105"))
    # Display name in the host table. Empty means "use the machine's real
    # hostname", which is the honest default; override when the VM's hostname
    # differs from the name the topology diagram uses.
    victim_hostname: str = field(default_factory=lambda: _env_str("SOC_VICTIM_HOSTNAME", ""))

    # --- Log sources --------------------------------------------------------
    auth_log_path: str = field(default_factory=lambda: _env_str("SOC_AUTH_LOG", "/var/log/auth.log"))
    kern_log_path: str = field(default_factory=lambda: _env_str("SOC_KERN_LOG", "/var/log/kern.log"))
    enable_ufw_collector: bool = field(default_factory=lambda: _env_bool("SOC_ENABLE_UFW", True))
    enable_new_connection: bool = field(
        default_factory=lambda: _env_bool("SOC_ENABLE_NEW_CONNECTION", True)
    )

    # --- Timing -------------------------------------------------------------
    tail_poll_seconds: float = field(default_factory=lambda: _env_float("SOC_TAIL_POLL_S", 0.5))
    telemetry_interval_seconds: float = field(
        default_factory=lambda: _env_float("SOC_TELEMETRY_INTERVAL_S", 5.0)
    )
    backfill_window_seconds: int = field(
        default_factory=lambda: _env_int("SOC_BACKFILL_WINDOW_S", 24 * 60 * 60)
    )

    # --- Detection thresholds ----------------------------------------------
    brute_force_window_seconds: int = field(default_factory=lambda: _env_int("SOC_BF_WINDOW_S", 60))
    brute_force_threshold: int = field(default_factory=lambda: _env_int("SOC_BF_THRESHOLD", 5))
    brute_force_cooldown_seconds: int = field(default_factory=lambda: _env_int("SOC_BF_COOLDOWN_S", 300))

    port_scan_window_seconds: int = field(default_factory=lambda: _env_int("SOC_PS_WINDOW_S", 60))
    port_scan_threshold: int = field(default_factory=lambda: _env_int("SOC_PS_THRESHOLD", 10))
    port_scan_cooldown_seconds: int = field(default_factory=lambda: _env_int("SOC_PS_COOLDOWN_S", 300))

    # A successful login within this window of recent failures is escalated.
    login_escalation_lookback_seconds: int = field(
        default_factory=lambda: _env_int("SOC_LOGIN_ESCALATION_S", 900)
    )
    login_escalation_min_failures: int = field(
        default_factory=lambda: _env_int("SOC_LOGIN_ESCALATION_FAILS", 3)
    )

    # --- Store --------------------------------------------------------------
    # Above the frontend's MAX_RETAINED_EVENTS (12_000) so a 24h query is never
    # truncated by the buffer before the time filter applies.
    store_capacity: int = field(default_factory=lambda: _env_int("SOC_STORE_CAPACITY", 20_000))
    query_limit: int = field(default_factory=lambda: _env_int("SOC_QUERY_LIMIT", 5_000))

    # --- WebSocket ----------------------------------------------------------
    ws_queue_size: int = field(default_factory=lambda: _env_int("SOC_WS_QUEUE", 500))
    # Replay-on-connect closes the gap where events emitted between the HTTP
    # snapshot and the socket opening are lost. Safe only once the frontend
    # dedupes by id — ship 0 until that lands.
    ws_replay_seconds: int = field(default_factory=lambda: _env_int("SOC_WS_REPLAY_SECONDS", 120))
    ws_replay_max: int = field(default_factory=lambda: _env_int("SOC_WS_REPLAY_MAX", 200))

    # --- Server -------------------------------------------------------------
    cors_origin_regex: str = field(
        default_factory=lambda: _env_str(
            "SOC_CORS_ORIGIN_REGEX",
            r"http://(localhost|127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3})(:\d+)?",
        )
    )


settings = Settings()
