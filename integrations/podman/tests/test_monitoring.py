#!/usr/bin/env python3

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import ssl

MANAGER_CONTAINER = os.environ.get("WAZUH_MANAGER_CONTAINER", "podman-single-node_wazuh.manager_1")
AGENT_CONTAINER = os.environ.get("WAZUH_AGENT_CONTAINER", "wazuh-agent-podman")
ALERTS = os.environ.get("WAZUH_ALERTS", "/var/ossec/logs/alerts/alerts.json")
TIMEOUT = int(os.environ.get("WAZUH_TEST_TIMEOUT", "90"))
INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
DASHBOARD_URL = os.environ.get("WAZUH_DASHBOARD_URL", "https://localhost:8443")
CREDENTIALS = os.environ.get("WAZUH_CREDENTIALS", "admin:SecretPassword")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

PASSED = []
FAILED = []


def run(args, check=True):
    result = subprocess.run(args, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed: {result.stderr.strip()}")
    return result


def podman(*args, check=True):
    return run(["podman", *args], check=check)


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


def wait_for_rules(mark, rule_ids, timeout=TIMEOUT):
    deadline = time.time() + timeout
    found = set()
    alerts = []
    while time.time() < deadline:
        alerts = new_alerts(mark)
        found = {alert["rule"]["id"] for alert in alerts}
        if found & set(rule_ids):
            return found & set(rule_ids), alerts
        time.sleep(3)
    return set(), alerts


def force_benchmark():
    podman("exec", AGENT_CONTAINER, "python3", "/opt/podman-monitor/podman_monitor.py",
           "--once-benchmark")
    time.sleep(2)


def force_stats():
    podman("exec", AGENT_CONTAINER, "python3", "/opt/podman-monitor/podman_monitor.py",
           "--once-stats")
    time.sleep(2)


def force_inventory():
    podman("exec", AGENT_CONTAINER, "python3", "/opt/podman-monitor/podman_monitor.py",
           "--once-inventory")
    time.sleep(2)


def cleanup(name):
    podman("rm", "-f", name, check=False)
    for _ in range(10):
        if podman("container", "exists", name, check=False).returncode != 0:
            return
        time.sleep(1)


def cleanup_all():
    result = podman("ps", "-a", "--filter", "name=^test-", "--format", "{{.Names}}", check=False)
    for name in result.stdout.split():
        cleanup(name)


def warmup():
    cleanup("test-warmup")
    mark = alert_mark()
    podman("run", "-d", "--name", "test-warmup", "docker.io/library/alpine:latest", "sleep", "30")
    found, _ = wait_for_rules(mark, ["100100", "100101"], timeout=max(TIMEOUT, 120))
    cleanup("test-warmup")
    if found:
        print(f"PASS  agent warmup  ->  rules {sorted(found)}")
        PASSED.append("agent warmup")
        return True
    print("FAIL  agent warmup  ->  collector not reporting lifecycle events")
    FAILED.append("agent warmup")
    return False


def scenario(name, rule_ids, setup, timeout=TIMEOUT):
    cleanup(name)
    mark = alert_mark()
    setup()
    found, alerts = wait_for_rules(mark, rule_ids, timeout)
    cleanup(name)
    if found:
        PASSED.append(name)
        print(f"PASS  {name}  ->  rules {sorted(found)}")
        return alerts
    FAILED.append(name)
    observed = sorted({alert["rule"]["id"] for alert in alerts})
    print(f"FAIL  {name}  ->  expected {rule_ids}, observed {observed}")
    return alerts


def measurement(name, mark, predicate):
    alerts = new_alerts(mark)
    for alert in alerts:
        if predicate(alert):
            PASSED.append(name)
            print(f"PASS  {name}")
            return True
    FAILED.append(name)
    print(f"FAIL  {name}")
    return False


def test_lifecycle():
    alerts = scenario(
        "container create/start", ["100100", "100101"],
        lambda: podman("run", "-d", "--name", "test-lifecycle",
                       "docker.io/library/alpine:latest", "sleep", "30"),
    )
    starts = [a for a in alerts if a["rule"]["id"] == "100101"]
    if starts:
        startup = starts[0]["data"].get("podman", {}).get("startup_ms")
        if startup is not None:
            PASSED.append("startup time measured")
            print(f"PASS  startup time measured  ->  {startup} ms")
        else:
            FAILED.append("startup time measured")
            print("FAIL  startup time measured")


def test_stop():
    podman("run", "-d", "--name", "test-stop", "docker.io/library/alpine:latest", "sleep", "30")
    mark = alert_mark()
    time.sleep(2)
    podman("stop", "test-stop")
    found, _ = wait_for_rules(mark, ["100102", "100104"])
    cleanup("test-stop")
    if found:
        PASSED.append("container stop")
        print(f"PASS  container stop  ->  rules {sorted(found)}")
    else:
        FAILED.append("container stop")
        print("FAIL  container stop")


def test_crash():
    scenario(
        "crash exit 1", ["100105"],
        lambda: podman("run", "-d", "--name", "test-crash",
                       "docker.io/library/alpine:latest", "sh", "-c", "exit 1"),
    )


def test_sigkill():
    def setup():
        podman("run", "-d", "--name", "test-kill", "docker.io/library/alpine:latest", "sleep", "60")
        time.sleep(2)
        podman("kill", "test-kill")
    scenario("SIGKILL", ["100106", "100108"], setup)


def test_oom():
    def setup():
        podman("run", "-d", "--name", "test-oom", "--memory", "32m", "--ulimit", "core=0",
               "docker.io/library/python:3.12-alpine", "python3", "-c",
               "x=[]\nwhile True: x.append(bytearray(1024*1024))")
    scenario("out of memory", ["100106", "100107"], setup, timeout=max(TIMEOUT, 150))


def test_exec_shell():
    def setup():
        podman("run", "-d", "--name", "test-exec", "docker.io/library/alpine:latest", "sleep", "60")
        time.sleep(2)
        podman("exec", "test-exec", "sh", "-c", "echo hello")
    scenario("command execution", ["100110"], setup)


def test_health():
    def setup():
        podman("run", "-d", "--name", "test-health", "--health-cmd", "exit 1",
               "--health-interval", "1s", "--health-retries", "1", "--health-timeout", "1s",
               "docker.io/library/alpine:latest", "sleep", "60")
        time.sleep(5)
        force_benchmark()
    scenario("unhealthy container", ["100136"], setup)


def test_privileged():
    def setup():
        podman("run", "-d", "--name", "test-priv", "--privileged",
               "docker.io/library/alpine:latest", "sleep", "120")
        force_benchmark()
    scenario("privileged container", ["100133"], setup)


def test_host_network():
    def setup():
        podman("run", "-d", "--name", "test-hostnet", "--network", "host",
               "docker.io/library/alpine:latest", "sleep", "120")
        force_benchmark()
    scenario("host network", ["100132"], setup)


def test_sensitive_mount():
    def setup():
        podman("run", "-d", "--name", "test-mount", "-v", "/etc:/host-etc:ro",
               "docker.io/library/alpine:latest", "sleep", "120")
        force_benchmark()
    scenario("sensitive host mount", ["100132"], setup)


def test_no_limits():
    def setup():
        podman("run", "-d", "--name", "test-nolimits",
               "docker.io/library/alpine:latest", "sleep", "120")
        force_benchmark()
    scenario("missing resource limits", ["100131"], setup)


def test_latest_tag():
    def setup():
        podman("run", "-d", "--name", "test-latest", "docker.io/library/alpine",
               "sleep", "120")
        force_benchmark()
    scenario("floating image tag", ["100130"], setup)


def test_cpu_measurement():
    cleanup("test-cpu")
    podman("run", "-d", "--name", "test-cpu", "--cpus", "1",
           "docker.io/library/python:3.12-alpine", "python3", "-c", "while True: pass")
    time.sleep(6)
    force_stats()
    mark = alert_mark()
    force_stats()
    time.sleep(3)

    def predicate(alert):
        if alert["rule"]["id"] != "100121":
            return False
        return float(alert["data"]["podman"]["cpu_percent"]) >= 50
    measurement("CPU measurement above 50%", mark, predicate)
    cleanup("test-cpu")


def test_memory_measurement():
    cleanup("test-mem")
    podman("run", "-d", "--name", "test-mem", "--memory", "256m",
           "docker.io/library/python:3.12-alpine", "python3", "-c",
           "x=bytearray(235*1024*1024)\nimport time\ntime.sleep(60)")
    time.sleep(6)
    mark = alert_mark()
    force_stats()
    time.sleep(3)

    def predicate(alert):
        if alert["rule"]["id"] != "100122":
            return False
        return float(alert["data"]["podman"]["memory_percent"]) >= 50
    measurement("memory measurement above 50%", mark, predicate)
    cleanup("test-mem")


def api(path, base=INDEXER_URL, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    import base64
    req.add_header("Authorization", "Basic " + base64.b64encode(CREDENTIALS.encode()).decode())
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, context=CTX) as response:
        return json.loads(response.read() or b"{}")


def test_indexer():
    force_inventory()
    required = {"podman.event", "podman.stats", "podman.benchmark", "podman.inventory"}
    types = set()
    for _ in range(8):
        time.sleep(4)
        try:
            result = api("/wazuh-alerts-*/_search", body={
                "size": 0,
                "aggs": {"types": {"terms": {"field": "data.event_type", "size": 20}}},
            })
            types = {b["key"] for b in result["aggregations"]["types"]["buckets"]}
        except Exception:
            types = set()
        if required <= types:
            break
    missing = required - types
    if missing:
        FAILED.append("indexer event coverage")
        print(f"FAIL  indexer event coverage  ->  missing {sorted(missing)}")
    else:
        PASSED.append("indexer event coverage")
        print(f"PASS  indexer event coverage  ->  {sorted(types)}")


def test_dashboard():
    try:
        import base64
        req = urllib.request.Request(DASHBOARD_URL + "/api/saved_objects/dashboard/podman-overview")
        req.add_header("Authorization", "Basic " + base64.b64encode(CREDENTIALS.encode()).decode())
        req.add_header("osd-xsrf", "true")
        with urllib.request.urlopen(req, context=CTX) as response:
            obj = json.loads(response.read())
        panels = len(json.loads(obj["attributes"]["panelsJSON"]))
        if panels >= 8:
            PASSED.append("dashboard saved object")
            print(f"PASS  dashboard saved object  ->  {panels} panels")
        else:
            FAILED.append("dashboard saved object")
            print(f"FAIL  dashboard saved object  ->  only {panels} panels")
    except Exception as error:
        FAILED.append("dashboard saved object")
        print(f"FAIL  dashboard saved object  ->  {error}")


def main():
    print("== Wazuh Podman monitoring test suite ==\n")
    os.chdir(tempfile.mkdtemp(prefix="wazuh-podman-tests-"))
    cleanup_all()
    warmup()
    test_lifecycle()
    test_stop()
    test_crash()
    test_sigkill()
    test_oom()
    test_exec_shell()
    test_health()
    test_privileged()
    test_host_network()
    test_sensitive_mount()
    test_no_limits()
    test_latest_tag()
    test_cpu_measurement()
    test_memory_measurement()
    test_indexer()
    test_dashboard()

    print(f"\n== {len(PASSED)} passed, {len(FAILED)} failed ==")
    if FAILED:
        print("failed: " + ", ".join(FAILED))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
