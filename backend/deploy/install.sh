#!/usr/bin/env bash
#
# Installs the SOC detection engine on the Ubuntu victim.
#
#   sudo ./deploy/install.sh
#
# Idempotent: safe to re-run after pulling changes.
set -euo pipefail

APP_DIR=/opt/soc-engine
ENV_DIR=/etc/soc-engine
SERVICE_USER=soc-engine
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo." >&2
  exit 1
fi

echo "==> Creating service user"
if ! id "$SERVICE_USER" &>/dev/null; then
  adduser --system --group --no-create-home --home /nonexistent "$SERVICE_USER"
fi
# auth.log and kern.log are root:adm 0640 — group membership is how a non-root
# service reads them. Running as root would be the lazy alternative.
usermod -aG adm "$SERVICE_USER"

echo "==> Verifying log access as $SERVICE_USER"
if runuser -u "$SERVICE_USER" -- head -n1 /var/log/auth.log >/dev/null 2>&1; then
  echo "    auth.log readable"
else
  echo "    WARNING: cannot read /var/log/auth.log as $SERVICE_USER." >&2
  echo "    The engine will start but produce no events." >&2
fi

echo "==> Installing application to $APP_DIR"
mkdir -p "$APP_DIR"
cp -r "$SRC_DIR/soc_engine" "$SRC_DIR/requirements.txt" "$APP_DIR/"
[[ -d "$SRC_DIR/tools" ]] && cp -r "$SRC_DIR/tools" "$APP_DIR/"
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"

echo "==> Creating virtualenv"
if [[ ! -x "$APP_DIR/.venv/bin/python" ]]; then
  python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/.venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"

echo "==> Installing configuration"
mkdir -p "$ENV_DIR"
if [[ ! -f "$ENV_DIR/soc-engine.env" ]]; then
  cp "$SRC_DIR/deploy/soc-engine.env" "$ENV_DIR/"
  echo "    wrote $ENV_DIR/soc-engine.env"
else
  echo "    $ENV_DIR/soc-engine.env exists — left untouched"
fi

echo "==> Installing systemd unit"
cp "$SRC_DIR/deploy/soc-engine.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now soc-engine

sleep 2
echo
echo "==> Status"
systemctl --no-pager --lines=0 status soc-engine || true
echo
echo "==> Health"
curl -fsS http://127.0.0.1:8000/healthz 2>/dev/null || echo "    not responding yet — check: journalctl -u soc-engine -f"
echo
echo "Done. On the machine running the dashboard, set:"
echo "    VITE_SOC_API_URL=http://$(hostname -I | awk '{print $1}'):8000"
echo "and RESTART the Vite dev server (VITE_ vars are build-time)."
