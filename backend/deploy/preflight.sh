#!/usr/bin/env bash
#
# Reports what this host can actually feed the dashboard, before installing.
# Read-only — changes nothing.
#
#   ./deploy/preflight.sh

echo "=== SOC detection engine preflight ==="
echo

pass() { echo "  [ OK ] $1"; }
warn() { echo "  [WARN] $1"; }
fail() { echo "  [FAIL] $1"; }

echo "Python"
if command -v python3 >/dev/null; then
  pass "$(python3 --version)"
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' \
    || warn "Python 3.10+ recommended (uses X | Y type syntax)"
else
  fail "python3 not found — apt install python3 python3-venv"
fi
python3 -c 'import venv' 2>/dev/null && pass "venv module present" \
  || warn "venv missing — apt install python3-venv"
echo

echo "Log sources"
for f in /var/log/auth.log /var/log/kern.log; do
  if [[ -r "$f" ]]; then
    pass "$f readable by $(whoami) ($(stat -c '%U:%G %a' "$f"))"
  elif [[ -e "$f" ]]; then
    warn "$f exists but is not readable by $(whoami) ($(stat -c '%U:%G %a' "$f")) — the service user needs the 'adm' group"
  else
    fail "$f does not exist"
  fi
done
echo

echo "Detections this host can produce"
if [[ -e /var/log/auth.log ]]; then
  pass "ssh_failed_auth, suspicious_login, successful_login, ssh_brute_force, privilege_escalation"
else
  fail "auth.log missing — no SSH or sudo detections at all"
fi

if command -v ufw >/dev/null; then
  status=$(ufw status 2>/dev/null | head -1)
  logging=$(ufw status verbose 2>/dev/null | grep -i '^Logging:' || echo "Logging: unknown")
  if echo "$status" | grep -qi active; then
    if echo "$logging" | grep -qi 'on'; then
      pass "port_scan (ufw active, $logging)"
    else
      warn "port_scan unavailable — ufw is active but $logging. Run: sudo ufw logging on"
    fi
  else
    warn "port_scan unavailable — ufw is inactive."
    echo "         Before enabling, ALLOW SSH or you will lock yourself out:"
    echo "           sudo ufw allow 22/tcp && sudo ufw allow 8000/tcp"
    echo "           sudo ufw enable && sudo ufw logging on"
  fi
else
  warn "port_scan unavailable — ufw not installed"
fi
echo "  [ -- ] web_attack, malware_signature, suspicious_process, data_exfiltration:"
echo "         no data source on this host. These are never emitted rather than faked."
echo

echo "Network reachability"
ip=$(hostname -I 2>/dev/null | awk '{print $1}')
[[ -n "$ip" ]] && pass "primary address $ip — dashboard should use http://$ip:8000" \
               || warn "could not determine an IP address"
if command -v ss >/dev/null && ss -lntp 2>/dev/null | grep -q ':8000'; then
  warn "something is already listening on port 8000"
else
  pass "port 8000 is free"
fi
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -qi active; then
  ufw status 2>/dev/null | grep -q '8000' \
    && pass "ufw permits port 8000" \
    || warn "ufw is active but has no rule for 8000 — run: sudo ufw allow from 192.168.56.0/24 to any port 8000 proto tcp"
fi
echo

echo "sshd"
if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
  pass "sshd is running (required for SSH detections to have anything to see)"
  grep -qiE '^\s*PasswordAuthentication\s+yes' /etc/ssh/sshd_config 2>/dev/null \
    && pass "PasswordAuthentication yes — hydra tests will produce failures" \
    || warn "PasswordAuthentication is not enabled; password brute-force attempts will be rejected before they log a failure"
else
  warn "sshd is not running — no SSH events will be generated"
fi
echo
echo "=== end preflight ==="
