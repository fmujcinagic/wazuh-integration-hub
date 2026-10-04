#!/usr/bin/env python3

import base64
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request

MANAGER_CONTAINER = os.environ.get("WAZUH_MANAGER_CONTAINER", "wazuh.manager")
KEYCLOAK_CONTAINER = os.environ.get("KEYCLOAK_CONTAINER", "keycloak-test")
KEYCLOAK_IMAGE = os.environ.get("KEYCLOAK_IMAGE", "quay.io/keycloak/keycloak:26.4")
KEYCLOAK_PORT = os.environ.get("KEYCLOAK_PORT", "18080")
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", f"http://localhost:{KEYCLOAK_PORT}")
KC_ADMIN = os.environ.get("KC_ADMIN", "monitor-admin")
KC_PASSWORD = os.environ.get("KC_PASSWORD", "monitor-password")
KEYCLOAK_LOG = os.environ.get("KEYCLOAK_LOG", os.path.expanduser("~/.local/state/keycloak/keycloak.json"))
ALERTS = os.environ.get("WAZUH_ALERTS", "/var/ossec/logs/alerts/alerts.json")
TIMEOUT = int(os.environ.get("WAZUH_TEST_TIMEOUT", "180"))
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


def start_keycloak():
    podman("rm", "-f", KEYCLOAK_CONTAINER, check=False)
    log_dir = os.path.dirname(KEYCLOAK_LOG)
    os.makedirs(log_dir, exist_ok=True)
    subprocess.Popen(
        ["podman", "run", "--rm", "--name", KEYCLOAK_CONTAINER,
         "-p", f"{KEYCLOAK_PORT}:8080",
         "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=" + KC_ADMIN,
         "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=" + KC_PASSWORD,
         KEYCLOAK_IMAGE, "start-dev", "--http-port=8080"],
        stdout=open(KEYCLOAK_LOG, "wb"),
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
    )
    deadline = time.time() + 180
    while time.time() < deadline:
        for line in open(KEYCLOAK_LOG, encoding="utf-8", errors="ignore"):
            if "Listening on:" in line or "http://0.0.0.0:8080" in line:
                return
        time.sleep(4)
    raise RuntimeError("keycloak did not become ready")


def http(url, body=None, headers=None):
    data = None
    if body is not None:
        data = urllib.parse.urlencode(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        payload = error.read() or b"{}"
        return error.code, json.loads(payload)


def enable_events_listener(admin_token):
    body = json.dumps({
        "eventsListeners": ["jboss-logging"],
        "eventsEnabled": True,
        "adminEventsEnabled": True,
        "adminEventsDetailsEnabled": True,
    }).encode()
    req = urllib.request.Request(
        f"{KEYCLOAK_URL}/admin/realms/master/events/config", data=body, method="PUT",
        headers={"Authorization": "Bearer " + admin_token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as response:
            return response.status in (200, 204)
    except urllib.error.HTTPError as error:
        print(f"      event listener config -> {error.code} {error.read().decode(errors='ignore')[:200]}")
        return False


def drive_logins():
    public_token = http(f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token", body={
        "client_id": "admin-cli", "username": KC_ADMIN, "password": KC_PASSWORD,
        "grant_type": "password",
    })[1].get("access_token")
    if public_token:
        PASSED.append("successful login")
        print("PASS  successful login -> token endpoint accepted the credentials")
    else:
        FAILED.append("successful login")
        print("FAIL  successful login -> no access token in the response")
    failed = []
    for _ in range(2):
        status, _ = http(f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token", body={
            "client_id": "admin-cli", "username": "ghost-user", "password": "wrong-password",
            "grant_type": "password",
        })
        failed.append(status == 401)
    if all(failed):
        PASSED.append("failed logins")
        print("PASS  failed logins -> token endpoint rejected the credentials")
    else:
        FAILED.append("failed logins")
        print("FAIL  failed logins -> unexpected status codes")


def keycloak_event_lines():
    events, admin = [], []
    for line in open(KEYCLOAK_LOG, encoding="utf-8", errors="replace"):
        if '"loggerName":"' in line:
            try:
                decoded = json.loads(line)
            except json.JSONDecodeError:
                continue
            logger = str(decoded.get("loggerName", ""))
        elif "[org.keycloak.events]" in line:
            logger = "org.keycloak.events"
        else:
            continue
        if logger.startswith("org.keycloak.events"):
            events.append(line.rstrip("\n"))
        elif "admin" in logger:
            admin.append(line.rstrip("\n"))
    return events, admin


def inject(event):
    with open(KEYCLOAK_LOG, "a", encoding="utf-8") as handle:
        handle.write(event + "\n")
        handle.flush()


def test_events():
    events, admin = keycloak_event_lines()
    if events:
        PASSED.append("event listener log")
        print(f"PASS  event listener log -> {len(events)} user event lines")
    else:
        FAILED.append("event listener log")
        print("FAIL  event listener log -> no user events reached the log")
    return events, admin


def sample_events():
    samples = []
    mark = alert_mark()
    inject('{"event_type":"keycloak.login","keycloak":{"type":"LOGIN","realm":"master","user":"monitor-admin","ip":"127.0.0.1"}}')
    samples.append(("canonical login rule", '102010'))
    inject('{"event_type":"keycloak.login","keycloak":{"type":"LOGIN_ERROR","realm":"master","user":"ghost-user","ip":"127.0.0.1","error":"user_not_found"}}')
    samples.append(("canonical enumeration rule", '102013'))
    inject('{"event_type":"keycloak.login","keycloak":{"type":"LOGIN_ERROR","realm":"master","user":"monitor-admin","ip":"127.0.0.1","error":"invalid_grant"}}')
    samples.append(("canonical credentials rule", '102012'))
    return mark, samples


def drive_listener(mark):
    inject('2026-09-30 22:39:23,457 WARN  [org.keycloak.events] (executor-thread-1) type="LOGIN_ERROR", realmId="3bd4bdc4-cb22-4837-b6cb-10b3164b586c", realmName="master", clientId="admin-cli", userId="null", ipAddress="192.168.1.40", error="user_not_found", auth_method="openid-connect", grant_type="password", client_auth_method="client-secret", username="ghost-user"')
    found, observed = wait_for_rule(mark, '102003')
    if found:
        PASSED.append("listener enumeration rule")
        print("PASS  listener enumeration rule  ->  102003")
    else:
        FAILED.append("listener enumeration rule")
        print(f"FAIL  listener enumeration rule  ->  expected 102003, observed {sorted(observed)}")


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
        mapping = api("/wazuh-alerts-*/_mapping/field/data.keycloak.error")
        for index in mapping.values():
            for info in index.get("mappings", {}).values():
                if info.get("mapping", {}).get("error", {}).get("type") == "keyword":
                    PASSED.append("index mapping")
                    print("PASS  index mapping -> data.keycloak.error is keyword")
                    return
        raise RuntimeError("error is not keyword")
    except Exception as error:
        FAILED.append("index mapping")
        print(f"FAIL  index mapping -> {error}")


def test_dashboard():
    try:
        req = urllib.request.Request(DASHBOARD_URL + "/api/saved_objects/dashboard/keycloak-overview")
        req.add_header("Authorization", "Basic " + base64.b64encode(CREDENTIALS.encode()).decode())
        req.add_header("osd-xsrf", "true")
        with urllib.request.urlopen(req, context=CTX) as response:
            obj = json.loads(response.read())
        panels = len(json.loads(obj["attributes"]["panelsJSON"]))
        if panels >= 5:
            PASSED.append("dashboard saved object")
            print(f"PASS  dashboard saved object -> {panels} panels")
        else:
            FAILED.append("dashboard saved object")
            print(f"FAIL  dashboard saved object -> only {panels} panels")
    except Exception as error:
        FAILED.append("dashboard saved object")
        print(f"FAIL  dashboard saved object -> {error}")


def cleanup():
    try:
        podman("rm", "-f", KEYCLOAK_CONTAINER, check=False)
    except Exception:
        pass


def main():
    try:
        start_keycloak()
        admin_token = http(f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token", body={
            "client_id": "admin-cli", "username": KC_ADMIN, "password": KC_PASSWORD,
            "grant_type": "password",
        })[1].get("access_token")
        if admin_token is None:
            FAILED.append("keycloak bootstrap")
            print("FAIL  keycloak bootstrap -> no admin token")
            return 1
        if enable_events_listener(admin_token):
            PASSED.append("event listener")
            print("PASS  event listener -> jboss-logging registered")
        else:
            FAILED.append("event listener")
            print("FAIL  event listener -> admin API rejected the update")
        drive_logins()
        events, admin = test_events()
        drive_listener(alert_mark())
        mark, samples = sample_events()
        for name, rule in samples:
            found, observed = wait_for_rule(mark, rule)
            if found:
                PASSED.append(name)
                print(f"PASS  {name}  ->  {rule}")
            else:
                FAILED.append(name)
                print(f"FAIL  {name}  ->  expected {rule}, observed {sorted(observed)}")
        test_mappings()
        test_dashboard()
    except Exception as error:
        FAILED.append("setup")
        print(f"FAIL  setup -> {error}")
    finally:
        cleanup()
    print("")
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
