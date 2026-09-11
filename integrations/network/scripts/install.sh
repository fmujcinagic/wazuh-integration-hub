#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANAGER="${WAZUH_MANAGER_SERVER:-127.0.0.1}"
BIN_DIR="$HOME/.local/share/wazuh-network"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
STATE_DIR="$HOME/.local/state/wazuh-network"

mkdir -p "$BIN_DIR" "$UNIT_DIR" "$STATE_DIR" "$HOME/.config"
install -m 0755 "$HERE/network_monitor.py" "$BIN_DIR/network_monitor.py"
install -m 0644 "$HERE/network-monitor.service" "$UNIT_DIR/network-monitor.service"
printf 'WAZUH_MANAGER_SERVER=%s\n' "$MANAGER" > "$HOME/.config/wazuh-network.conf"

systemctl --user daemon-reload
systemctl --user enable --now network-monitor.service

echo "network monitor installed, logging to $STATE_DIR/network.json"
