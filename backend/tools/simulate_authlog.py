"""
Writes a synthetic auth.log so the engine can be exercised without an Ubuntu VM.

Two modes:

    python tools/simulate_authlog.py seed <path>     # 24h of history, then exit
    python tools/simulate_authlog.py live <path>     # append plausible traffic forever
    python tools/simulate_authlog.py attack <path>   # one brute-force burst, then exit

The lines are byte-identical in format to what sshd writes, so this exercises
the real parsers rather than a test-only shortcut.
"""

from __future__ import annotations

import random
import sys
import time
from datetime import datetime, timedelta

ATTACKER = "192.168.56.106"
SECONDARY = "192.168.56.107"
EXTERNAL = "10.10.10.24"
USERS = ["root", "admin", "ubuntu", "postgres", "deploy", "test", "oracle"]

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def stamp(moment: datetime) -> str:
    """Traditional syslog format, space-padded day."""
    return f"{MONTHS[moment.month - 1]} {moment.day:>2} {moment:%H:%M:%S}"


def failed(moment: datetime, user: str, ip: str, pid: int, port: int) -> str:
    return (
        f"{stamp(moment)} ubuntu-victim sshd[{pid}]: "
        f"Failed password for {user} from {ip} port {port} ssh2"
    )


def invalid(moment: datetime, user: str, ip: str, pid: int, port: int) -> str:
    return (
        f"{stamp(moment)} ubuntu-victim sshd[{pid}]: "
        f"Failed password for invalid user {user} from {ip} port {port} ssh2"
    )


def accepted(moment: datetime, user: str, ip: str, pid: int, port: int) -> str:
    return (
        f"{stamp(moment)} ubuntu-victim sshd[{pid}]: "
        f"Accepted password for {user} from {ip} port {port} ssh2"
    )


def pam_noise(moment: datetime, user: str, ip: str, pid: int) -> str:
    """A line the parser MUST ignore — included so seeds exercise that path."""
    return (
        f"{stamp(moment)} ubuntu-victim sshd[{pid}]: pam_unix(sshd:auth): "
        f"authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}"
    )


def sudo_fail(moment: datetime, user: str, pid: int) -> str:
    return (
        f"{stamp(moment)} ubuntu-victim sudo:   {user} : 3 incorrect password attempts ; "
        f"TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/id"
    )


def seed(path: str) -> None:
    """24 hours of plausible history, quiet overnight and busier by day."""
    now = datetime.now()
    lines: list[str] = []
    pid = 10000

    for minutes_ago in range(24 * 60, 0, -1):
        moment = now - timedelta(minutes=minutes_ago)
        hour = moment.hour
        density = 0.45 if 9 <= hour <= 18 else 0.08
        if random.random() > density:
            continue

        pid += random.randint(1, 5)
        port = random.randint(32768, 61000)
        user = random.choice(USERS)
        ip = random.choices([ATTACKER, SECONDARY, EXTERNAL], weights=[6, 3, 2])[0]
        roll = random.random()

        if roll < 0.5:
            lines.append(pam_noise(moment, user, ip, pid))
            lines.append(failed(moment, user, ip, pid, port))
        elif roll < 0.75:
            lines.append(invalid(moment, user, ip, pid, port))
        elif roll < 0.9:
            lines.append(accepted(moment, "ubuntu", ip, pid, port))
        else:
            lines.append(sudo_fail(moment, "deploy", pid))

    # A brute-force burst 40 minutes back, so the dashboard opens with a real
    # critical alert in the recent window.
    burst_start = now - timedelta(minutes=40)
    for i in range(9):
        moment = burst_start + timedelta(seconds=i * 4)
        lines.append(failed(moment, "root", ATTACKER, 24800 + i, 51000 + i))

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"Seeded {len(lines)} lines into {path}")


def live(path: str) -> None:
    """Appends ambient traffic indefinitely, with an occasional burst."""
    pid = 40000
    print(f"Appending to {path} — Ctrl+C to stop")
    while True:
        pid += random.randint(1, 4)
        moment = datetime.now()
        port = random.randint(32768, 61000)
        user = random.choice(USERS)
        ip = random.choices([ATTACKER, SECONDARY, EXTERNAL], weights=[6, 3, 2])[0]

        batch: list[str] = []
        roll = random.random()
        if roll < 0.55:
            batch.append(pam_noise(moment, user, ip, pid))
            batch.append(failed(moment, user, ip, pid, port))
        elif roll < 0.8:
            batch.append(invalid(moment, user, ip, pid, port))
        elif roll < 0.9:
            batch.append(accepted(moment, "ubuntu", ip, pid, port))
        else:
            batch.append(sudo_fail(moment, "deploy", pid))

        with open(path, "a", encoding="utf-8") as handle:
            handle.write("\n".join(batch) + "\n")
        print(f"  + {batch[-1][:90]}")
        time.sleep(random.uniform(2.0, 6.0))


def attack(path: str) -> None:
    """One brute-force burst that must trip the correlator."""
    pid = 60000
    lines = []
    now = datetime.now()
    for i in range(8):
        lines.append(failed(now, "root", ATTACKER, pid + i, 55000 + i))
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"Injected {len(lines)} failures from {ATTACKER} into {path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        raise SystemExit(2)
    mode, target = sys.argv[1], sys.argv[2]
    {"seed": seed, "live": live, "attack": attack}[mode](target)
