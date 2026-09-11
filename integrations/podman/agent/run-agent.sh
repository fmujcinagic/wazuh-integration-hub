#!/usr/bin/env bash
set -euo pipefail

MANAGER_SERVER="${WAZUH_MANAGER_SERVER:-192.168.122.1}"
AGENT_NAME="${WAZUH_AGENT_NAME:-$(hostname -s)}"
AGENT_GROUP="${WAZUH_AGENT_GROUP:-podman}"
SOCKET="${PODMAN_SOCKET:-/run/user/$(id -u)/podman/podman.sock}"
NETWORK_LOG_DIR="${NETWORK_MONITOR_LOG_DIR:-$HOME/.local/state/wazuh-network}"
IMAGE="${AGENT_IMAGE:-wazuh-agent-podman:4.14.7}"
CONTAINER="${AGENT_CONTAINER:-wazuh-agent-podman}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SELINUX_OPTS=()
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = "Enforcing" ]; then
    SELINUX_OPTS=(--security-opt label=disable)
fi

podman build -t "$IMAGE" "$HERE"

podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
podman run -d \
    --name "$CONTAINER" \
    --restart always \
    --hostname "$AGENT_NAME" \
    "${SELINUX_OPTS[@]}" \
    -e WAZUH_MANAGER_SERVER="$MANAGER_SERVER" \
    -e WAZUH_REGISTRATION_SERVER="$MANAGER_SERVER" \
    -e WAZUH_AGENT_NAME="$AGENT_NAME" \
    -e WAZUH_AGENT_GROUP="$AGENT_GROUP" \
    -e DOCKER_HOST=unix:///var/run/docker.sock \
    -v "$SOCKET":/var/run/docker.sock \
    -v "$NETWORK_LOG_DIR":/var/log/network:ro \
    -v wazuh-agent-etc:/var/ossec/etc \
    -v wazuh-agent-queue:/var/ossec/queue \
    -v "$HERE/ossec.conf":/wazuh-config-mount/etc/ossec.conf:ro \
    "$IMAGE"

echo "started $CONTAINER (agent $AGENT_NAME) against $MANAGER_SERVER"
