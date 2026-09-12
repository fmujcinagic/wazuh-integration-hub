#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$HOME/.local/share/wazuh-podman"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
STATE_DIR="$HOME/.local/state/wazuh-podman"

mkdir -p "$BIN_DIR" "$UNIT_DIR" "$STATE_DIR"

python3 -m venv "$BIN_DIR/venv"
"$BIN_DIR/venv/bin/pip" install --quiet --upgrade pip docker
install -m 0755 "$HERE/podman_monitor.py" "$BIN_DIR/podman_monitor.py"
install -m 0644 "$HERE/podman-monitor.service" "$UNIT_DIR/podman-monitor.service"

systemctl --user enable --now podman.socket
systemctl --user daemon-reload
systemctl --user enable --now podman-monitor.service

echo "podman monitor installed, logging to $STATE_DIR/podman.json"
