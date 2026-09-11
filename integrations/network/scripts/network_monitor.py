#!/usr/bin/env python3

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone


LOG_DIR = os.environ.get("NETWORK_MONITOR_LOG_DIR", "/var/log/network")
INTERVAL = int(os.environ.get("NETWORK_MONITOR_INTERVAL", "60"))
MANAGER = os.environ.get("WAZUH_MANAGER_SERVER", "")
WAZUH_PORTS = {1514, 1515, 55000}
MAX_LOG_BYTES = int(os.environ.get("NETWORK_MONITOR_MAX_LOG_BYTES", str(32 * 1024 * 1024)))


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Writer:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, event):
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
            handle.flush()
        try:
            if os.path.getsize(self.path) > MAX_LOG_BYTES:
                backup = self.path + ".1"
                if os.path.exists(backup):
                    os.remove(backup)
                os.rename(self.path, backup)
        except OSError:
            pass


def read_interfaces():
    interfaces = {}
    with open("/proc/net/dev", encoding="utf-8") as handle:
        for line in handle.readlines()[2:]:
            name, rest = line.split(":", 1)
            fields = rest.split()
            interfaces[name.strip()] = {
                "rx_bytes": int(fields[0]),
                "rx_packets": int(fields[1]),
                "rx_errors": int(fields[2]),
                "rx_dropped": int(fields[3]),
                "tx_bytes": int(fields[8]),
                "tx_packets": int(fields[9]),
                "tx_errors": int(fields[10]),
                "tx_dropped": int(fields[11]),
            }
    return interfaces


def read_snmp():
    counters = {}
    with open("/proc/net/snmp", encoding="utf-8") as handle:
        lines = handle.readlines()
    for index, line in enumerate(lines):
        if not line.startswith("Tcp:"):
            continue
        keys = line.split()[1:]
        values = lines[index + 1].split()[1:]
        counters = {key: int(value) for key, value in zip(keys, values) if value.isdigit()}
        break
    return counters


SS_PATTERN = re.compile(
    r"(?P<key>rtt|minrtt|bytes_sent|bytes_received|bytes_retrans|retrans|segs_out|segs_in|cwnd):(?P<value>[\d./]+)"
)


def parse_ss_detail(detail):
    values = {}
    for match in SS_PATTERN.finditer(detail):
        raw = match.group("value")
        if "/" in raw:
            raw = raw.split("/")[0]
        try:
            values[match.group("key")] = float(raw)
        except ValueError:
            continue
    return values


def read_connections():
    try:
        output = subprocess.run(
            ["ss", "-tin"], capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []

    connections = []
    current = None
    for line in output.splitlines():
        if line.startswith(("State", "Netid", "Recv-Q")):
            continue
        if line.startswith((" ", "\t")):
            if current is not None:
                current.update(parse_ss_detail(line))
            continue
        fields = line.split()
        if len(fields) < 5:
            continue
        local, peer = fields[3], fields[4]
        try:
            local_port = int(local.rsplit(":", 1)[1])
            peer_port = int(peer.rsplit(":", 1)[1])
        except (IndexError, ValueError):
            continue
        if peer_port not in WAZUH_PORTS and local_port not in WAZUH_PORTS:
            continue
        current = {
            "state": fields[0],
            "local": local,
            "peer": peer,
            "local_port": local_port,
            "peer_port": peer_port,
        }
        connections.append(current)
    return connections


def read_latency(target):
    if not target:
        return None
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", target],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"time=([\d.]+)\s*ms", result.stdout)
    if match:
        return float(match.group(1))
    return None


def emit_interfaces(writer, previous, current, elapsed):
    for name, counters in current.items():
        if name == "lo":
            continue
        if counters["rx_bytes"] == 0 and counters["tx_bytes"] == 0:
            continue
        event = {
            "event_type": "network.interface",
            "network": {"interface": name, **counters},
        }
        old = previous.get(name)
        if old:
            event["network"]["rx_rate_bps"] = int((counters["rx_bytes"] - old["rx_bytes"]) * 8 / elapsed)
            event["network"]["tx_rate_bps"] = int((counters["tx_bytes"] - old["tx_bytes"]) * 8 / elapsed)
        writer.write(event)


def emit_connections(writer, previous, connections, elapsed):
    for connection in connections:
        key = (connection["local"], connection["peer"])
        event = {
            "event_type": "network.connection",
            "network": {
                "local": connection["local"],
                "peer": connection["peer"],
                "state": connection["state"],
                "bytes_sent": int(connection.get("bytes_sent", 0)),
                "bytes_received": int(connection.get("bytes_received", 0)),
                "bytes_retrans": int(connection.get("bytes_retrans", 0)),
                "rtt_ms": round(connection.get("rtt", 0.0), 3),
                "minrtt_ms": round(connection.get("minrtt", 0.0), 3),
                "cwnd": int(connection.get("cwnd", 0)),
                "segs_out": int(connection.get("segs_out", 0)),
                "segs_in": int(connection.get("segs_in", 0)),
            },
        }
        old = previous.get(key)
        if old:
            sent = event["network"]["bytes_sent"] - old.get("bytes_sent", 0)
            received = event["network"]["bytes_received"] - old.get("bytes_received", 0)
            event["network"]["rate_sent_bps"] = int(sent * 8 / elapsed)
            event["network"]["rate_received_bps"] = int(received * 8 / elapsed)
        previous[key] = {
            "bytes_sent": event["network"]["bytes_sent"],
            "bytes_received": event["network"]["bytes_received"],
        }
        writer.write(event)


def emit_snmp(writer, previous, current, elapsed):
    if not current:
        return
    event = {
        "event_type": "network.snmp",
        "network": {
            "tcp_retrans_segs": current.get("RetransSegs", 0),
            "tcp_out_segs": current.get("OutSegs", 0),
            "tcp_in_segs": current.get("InSegs", 0),
            "tcp_in_errs": current.get("InErrs", 0),
        },
    }
    if previous:
        event["network"]["retrans_rate"] = round(
            (current.get("RetransSegs", 0) - previous.get("RetransSegs", 0)) / elapsed, 4
        )
    writer.write(event)


def emit_latency(writer, target, rtt):
    if rtt is None:
        return
    writer.write({
        "event_type": "network.latency",
        "network": {"target": target, "rtt_ms": round(rtt, 3)},
    })


def emit_wazuh(writer, previous, connections, elapsed):
    sent = sum(int(c.get("bytes_sent", 0)) for c in connections)
    received = sum(int(c.get("bytes_received", 0)) for c in connections)
    retrans = sum(int(c.get("bytes_retrans", 0)) for c in connections)
    rtts = [c.get("rtt", 0.0) for c in connections if c.get("rtt")]
    event = {
        "event_type": "network.wazuh",
        "network": {
            "manager": MANAGER,
            "connections": len(connections),
            "bytes_sent": sent,
            "bytes_received": received,
            "bytes_retrans": retrans,
            "rtt_ms": round(max(rtts), 3) if rtts else 0.0,
        },
    }
    if previous:
        event["network"]["rate_sent_bps"] = int((sent - previous.get("bytes_sent", 0)) * 8 / elapsed)
        event["network"]["rate_received_bps"] = int((received - previous.get("bytes_received", 0)) * 8 / elapsed)
        event["network"]["retrans_rate"] = round(
            (retrans - previous.get("bytes_retrans", 0)) / elapsed, 4
        )
    previous["bytes_sent"] = sent
    previous["bytes_received"] = received
    previous["bytes_retrans"] = retrans
    writer.write(event)


def sample(writer, state):
    now = time.monotonic()
    elapsed = max(now - state.get("last_time", now - INTERVAL), 0.001)
    interfaces = read_interfaces()
    connections = read_connections()
    snmp = read_snmp()
    latency = read_latency(MANAGER)

    emit_interfaces(writer, state.get("interfaces", {}), interfaces, elapsed)
    emit_connections(writer, state.setdefault("connections", {}), connections, elapsed)
    emit_wazuh(writer, state.setdefault("wazuh", {}), connections, elapsed)
    emit_snmp(writer, state.get("snmp"), snmp, elapsed)
    emit_latency(writer, MANAGER, latency)

    state["interfaces"] = interfaces
    state["snmp"] = snmp
    state["last_time"] = now


def main():
    writer = Writer(os.path.join(LOG_DIR, "network.json"))
    state = {}
    if "--once" in sys.argv:
        sample(writer, state)
        return
    while True:
        try:
            sample(writer, state)
        except Exception as error:
            sys.stderr.write(f"network sample failed: {error}\n")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
