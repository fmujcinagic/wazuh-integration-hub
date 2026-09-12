#!/usr/bin/env python3

import base64
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.request

MANAGER_CONTAINER = os.environ.get("WAZUH_MANAGER_CONTAINER", "wazuh.manager")
ALERTS = os.environ.get("WAZUH_ALERTS", "/var/ossec/logs/alerts/alerts.json")
NETWORK_LOG = os.environ.get("NETWORK_MONITOR_LOG", os.path.expanduser("~/.local/state/wazuh-network/network.json"))
TIMEOUT = int(os.environ.get("WAZUH_TEST_TIMEOUT", "90"))
INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
DASHBOARD_URL = os.environ.get("WAZUH_DASHBOARD_URL", "https://localhost:8443")
CREDENTIALS = os.environ.get("WAZUH_CREDENTIALS", "admin:SecretPassword")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

PASSED = []
FAILED = []


def podman(*args, check=True):
    result = subprocess.run(["podman", *args], capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return result


def alert_mark():
    result = podman("exec", MANAGER_CONTAINER, "sh", "-c", f"wc -l < {ALERTS}")
    return int(result.stdout.strip() or 0)


def new_alerts(mark):
    result = podman("exec", MANAGER_CONTAINER, "sh", "-c", f"tail -n +{mark + 1} {ALERTS}")
    alerts = []
    for line in result.stdout.splitlines():
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return alerts


def wait_for_rule(mark, rule_id, timeout=TIMEOUT):
    deadline = time.time() + timeout
    observed = set()
    while time.time() < deadline:
        observed = {alert["rule"]["id"] for alert in new_alerts(mark)}
        if rule_id in observed:
            return True, observed
        time.sleep(3)
    return False, observed


def inject(event):
    with open(NETWORK_LOG, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")
        handle.flush()


def scenario(name, event, rule_id):
    mark = alert_mark()
    inject(event)
    found, observed = wait_for_rule(mark, rule_id)
    if found:
        PASSED.append(name)
        print(f"PASS  {name}  ->  {rule_id}")
    else:
        FAILED.append(name)
        print(f"FAIL  {name}  ->  expected {rule_id}, observed {sorted(observed)}")


def test_collector():
    if not os.path.exists(NETWORK_LOG):
        FAILED.append("collector log")
        print(f"FAIL  collector log  ->  {NETWORK_LOG} not found")
        return
    types = set()
    with open(NETWORK_LOG, encoding="utf-8") as handle:
        for line in handle:
            try:
                types.add(json.loads(line)["event_type"])
            except (json.JSONDecodeError, KeyError):
                continue
    required = {"network.interface", "network.connection", "network.wazuh", "network.snmp", "network.latency"}
    missing = required - types
    if missing:
        FAILED.append("collector log")
        print(f"FAIL  collector log  ->  missing {sorted(missing)}")
    else:
        PASSED.append("collector log")
        print(f"PASS  collector log  ->  {sorted(types)}")


def api(path, base=INDEXER_URL, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method="POST" if data else "GET")
    req.add_header("Authorization", "Basic " + base64.b64encode(CREDENTIALS.encode()).decode())
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, context=CTX) as response:
        return json.loads(response.read() or b"{}")


def test_mappings():
    try:
        mapping = api("/wazuh-alerts-*/_mapping/field/data.network.rx_rate_bps")
        for index in mapping.values():
            for info in index.get("mappings", {}).values():
                if info.get("mapping", {}).get("rx_rate_bps", {}).get("type") == "long":
                    PASSED.append("index mapping")
                    print("PASS  index mapping  ->  data.network.rx_rate_bps is long")
                    return
        raise RuntimeError("rx_rate_bps is not long")
    except Exception as error:
        FAILED.append("index mapping")
        print(f"FAIL  index mapping  ->  {error}")


def test_dashboard():
    try:
        req = urllib.request.Request(DASHBOARD_URL + "/api/saved_objects/dashboard/network-overview")
        req.add_header("Authorization", "Basic " + base64.b64encode(CREDENTIALS.encode()).decode())
        req.add_header("osd-xsrf", "true")
        with urllib.request.urlopen(req, context=CTX) as response:
            obj = json.loads(response.read())
        panels = len(json.loads(obj["attributes"]["panelsJSON"]))
        if panels >= 6:
            PASSED.append("dashboard saved object")
            print(f"PASS  dashboard saved object  ->  {panels} panels")
        else:
            FAILED.append("dashboard saved object")
            print(f"FAIL  dashboard saved object  ->  only {panels} panels")
    except Exception as error:
        FAILED.append("dashboard saved object")
        print(f"FAIL  dashboard saved object  ->  {error}")


def main():
    print("== Wazuh network monitoring test suite ==\n")
    test_collector()
    scenario(
        "interface errors",
        {"event_type": "network.interface", "network": {"interface": "test0", "rx_errors": 5}},
        "101001",
    )
    scenario(
        "connection retransmissions",
        {"event_type": "network.connection", "network": {"local": "a", "peer": "b", "bytes_retrans": 2048}},
        "101011",
    )
    scenario(
        "connection latency",
        {"event_type": "network.connection", "network": {"local": "a", "peer": "b", "rtt_ms": 150.0}},
        "101012",
    )
    scenario(
        "wazuh disconnected",
        {"event_type": "network.wazuh", "network": {"manager": "192.168.122.1", "connections": 0}},
        "101021",
    )
    scenario(
        "wazuh retransmission rate",
        {"event_type": "network.wazuh", "network": {"manager": "192.168.122.1", "connections": 1, "retrans_rate": 2.5}},
        "101022",
    )
    scenario(
        "tcp retransmission rate",
        {"event_type": "network.snmp", "network": {"tcp_retrans_segs": 10, "retrans_rate": 25.0}},
        "101031",
    )
    scenario(
        "manager latency critical",
        {"event_type": "network.latency", "network": {"target": "192.168.122.1", "rtt_ms": 600.0}},
        "101042",
    )
    test_mappings()
    test_dashboard()

    print(f"\n== {len(PASSED)} passed, {len(FAILED)} failed ==")
    if FAILED:
        print("failed: " + ", ".join(FAILED))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
