#!/usr/bin/env python3

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone

try:
    import docker
except ImportError:
    sys.stderr.write("the 'docker' python module is required\n")
    sys.exit(1)


LOG_DIR = os.environ.get("PODMAN_MONITOR_LOG_DIR", "/var/log/podman")
STATS_INTERVAL = int(os.environ.get("PODMAN_STATS_INTERVAL", "60"))
BENCH_INTERVAL = int(os.environ.get("PODMAN_BENCH_INTERVAL", "900"))
INVENTORY_INTERVAL = int(os.environ.get("PODMAN_INVENTORY_INTERVAL", "3600"))
MAX_LOG_BYTES = int(os.environ.get("PODMAN_MONITOR_MAX_LOG_BYTES", str(64 * 1024 * 1024)))

SENSITIVE_HOST_PATHS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/podman/podman.sock",
    "/var/run/podman/podman.sock",
    "/var/run/containerd/containerd.sock",
)
SENSITIVE_MOUNT_PREFIXES = ("/", "/etc", "/proc", "/sys", "/root", "/home", "/var/run", "/run")

SEVERITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class JsonlWriter:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, event):
        line = json.dumps(event, separators=(",", ":"), default=str)
        with self.lock:
            self._rotate()
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()

    def _rotate(self):
        try:
            if os.path.exists(self.path) and os.path.getsize(self.path) > MAX_LOG_BYTES:
                backup = self.path + ".1"
                if os.path.exists(backup):
                    os.remove(backup)
                os.rename(self.path, backup)
        except OSError:
            pass


def cpu_percent(prev, current):
    try:
        cpu = current["cpu_stats"]["cpu_usage"]["total_usage"]
        pre = prev["cpu_stats"]["cpu_usage"]["total_usage"]
        system = current["cpu_stats"].get("system_cpu_usage", 0)
        presystem = prev["cpu_stats"].get("system_cpu_usage", 0)
        online = current["cpu_stats"].get("online_cpus") or len(
            current["cpu_stats"]["cpu_usage"].get("percpu_usage", []) or [1]
        )
        cpu_delta = cpu - pre
        system_delta = system - presystem
        if cpu_delta > 0 and system_delta > 0:
            return round((cpu_delta / system_delta) * online * 100.0, 2)
    except (KeyError, TypeError, ZeroDivisionError):
        pass
    return 0.0


def memory_usage(stats):
    try:
        usage = stats["memory_stats"].get("usage", 0)
        detail = stats["memory_stats"].get("stats", {})
        cache = detail.get("inactive_file", detail.get("cache", 0))
        limit = stats["memory_stats"].get("limit", 0)
        used = max(usage - cache, 0)
        percent = round((used / limit) * 100.0, 2) if limit else 0.0
        return used, limit, percent
    except (KeyError, TypeError):
        return 0, 0, 0.0


def network_io(stats):
    rx = tx = 0
    for iface in (stats.get("networks") or {}).values():
        rx += iface.get("rx_bytes", 0)
        tx += iface.get("tx_bytes", 0)
    return rx, tx


def block_io(stats):
    read = write = 0
    for item in (stats.get("blkio_stats") or {}).get("io_service_bytes_recursive") or []:
        if item.get("op") == "read":
            read += item.get("value", 0)
        elif item.get("op") == "write":
            write += item.get("value", 0)
    return read, write


def container_identity(container):
    attrs = container.attrs
    config = attrs.get("Config", {})
    state = attrs.get("State", {})
    return {
        "id": container.id[:12],
        "name": container.name,
        "image": config.get("Image", ""),
        "state": state.get("Status", ""),
    }


def stream_events(client, writer):
    state = {}
    for event in client.events(decode=True):
        action = event.get("Action", "")
        actor = event.get("Actor", {})
        attributes = actor.get("Attributes", {}) or {}
        key = actor.get("ID", event.get("id", ""))
        identity = {
            "id": key[:12],
            "name": attributes.get("name", ""),
            "image": attributes.get("image", event.get("from", "")),
        }
        stamp = event.get("time")
        try:
            timestamp = datetime.fromtimestamp(float(stamp), tz=timezone.utc)
        except (TypeError, ValueError):
            timestamp = datetime.now(timezone.utc)

        entry = state.setdefault(key, {})
        payload = {
            "action": action,
            "type": event.get("Type", ""),
            "container": identity,
            "attributes": attributes,
            "event_time": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        }

        if action == "create":
            entry["created"] = timestamp
        elif action == "start" and entry.get("created"):
            payload["startup_ms"] = int((timestamp - entry["created"]).total_seconds() * 1000)
            entry["started"] = timestamp
        elif action in ("die", "stop") and entry.get("started"):
            payload["uptime_ms"] = int((timestamp - entry["started"]).total_seconds() * 1000)

        exit_code = attributes.get("exitCode", attributes.get("containerExitCode"))
        if exit_code is not None and str(exit_code).lstrip("-").isdigit():
            payload["exit_code"] = int(exit_code)

        writer.write({"event_type": "podman.event", "podman": payload})


def collect_stats(client, writer):
    for container in client.containers.list():
        try:
            previous = container.stats(stream=False)
            time.sleep(0.4)
            raw = container.stats(stream=False)
            used, limit, percent = memory_usage(raw)
            rx, tx = network_io(raw)
            read, write = block_io(raw)
            writer.write({
                "event_type": "podman.stats",
                "podman": {
                    "container": container_identity(container),
                    "cpu_percent": cpu_percent(previous, raw),
                    "memory_used_bytes": used,
                    "memory_limit_bytes": limit,
                    "memory_percent": percent,
                    "network_rx_bytes": rx,
                    "network_tx_bytes": tx,
                    "block_read_bytes": read,
                    "block_write_bytes": write,
                    "pids": (raw.get("pids_stats") or {}).get("current", 0),
                },
            })
        except Exception as error:
            sys.stderr.write(f"stats failed for {container.name}: {error}\n")


def run_checks(container):
    attrs = container.attrs
    host = attrs.get("HostConfig", {})
    config = attrs.get("Config", {})
    state = attrs.get("State", {})
    mounts = attrs.get("Mounts", [])
    findings = []

    user = (config.get("User") or "").strip()
    if user in ("", "0", "root", "0:0"):
        findings.append(("PODMAN-001", "Container runs as root", "medium",
                         f"user='{user or 'root (default)'}'"))

    if host.get("Privileged"):
        findings.append(("PODMAN-002", "Privileged container", "critical",
                         "HostConfig.Privileged=true"))

    if host.get("NetworkMode") == "host":
        findings.append(("PODMAN-003", "Container uses host network namespace", "high",
                         "NetworkMode=host"))

    if host.get("PidMode") == "host":
        findings.append(("PODMAN-004", "Container uses host PID namespace", "high",
                         "PidMode=host"))

    if host.get("IpcMode") == "host":
        findings.append(("PODMAN-005", "Container uses host IPC namespace", "medium",
                         "IpcMode=host"))

    for mount in mounts:
        source = mount.get("Source", "")
        if source in SENSITIVE_HOST_PATHS:
            findings.append(("PODMAN-006", "Container runtime socket mounted", "critical",
                             f"mount {source} -> {mount.get('Destination')}"))
            break

    if not host.get("Memory") and not host.get("NanoCpus") and not host.get("CpuQuota"):
        findings.append(("PODMAN-007", "Container has no CPU or memory limits", "medium",
                         "Memory=0 NanoCpus=0"))

    caps = host.get("CapAdd") or []
    if caps:
        findings.append(("PODMAN-008", "Container adds Linux capabilities", "high",
                         f"CapAdd={','.join(caps)}"))

    if not host.get("ReadonlyRootfs"):
        findings.append(("PODMAN-009", "Container root filesystem is writable", "low",
                         "ReadonlyRootfs=false"))

    secopts = host.get("SecurityOpt") or []
    if not any("no-new-privileges" in option for option in secopts):
        findings.append(("PODMAN-010", "no-new-privileges is not set", "medium",
                         "SecurityOpt missing no-new-privileges"))

    for mount in mounts:
        source = mount.get("Source", "")
        destination = mount.get("Destination", "")
        if source in SENSITIVE_HOST_PATHS:
            continue
        if destination in SENSITIVE_MOUNT_PREFIXES or source in ("/", "/etc", "/proc", "/sys", "/root"):
            findings.append(("PODMAN-011", "Sensitive host path mounted", "high",
                             f"{source} -> {destination}"))
            break

    if not host.get("AppArmorProfile") and not host.get("SelinuxOptions"):
        findings.append(("PODMAN-012", "No mandatory access control profile", "medium",
                         "AppArmor/SELinux profile not applied"))

    image = config.get("Image", "")
    if image.endswith(":latest") or (":" not in image.rsplit("/", 1)[-1]):
        findings.append(("PODMAN-014", "Container image uses a floating tag", "low",
                         f"image={image}"))

    if state.get("OOMKilled"):
        findings.append(("PODMAN-015", "Container was OOM killed", "high",
                         "State.OOMKilled=true"))

    health = (state.get("Health") or {}).get("Status")
    if health == "unhealthy":
        findings.append(("PODMAN-016", "Container healthcheck is failing", "high",
                         "State.Health.Status=unhealthy"))

    return findings


def collect_benchmark(client, writer):
    scanned = 0
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for container in client.containers.list(all=True):
        scanned += 1
        identity = container_identity(container)
        try:
            for check_id, title, severity, evidence in run_checks(container):
                counts[severity] = counts.get(severity, 0) + 1
                writer.write({
                    "event_type": "podman.benchmark",
                    "podman": {
                        "check": {
                            "id": check_id,
                            "title": title,
                            "severity": severity,
                            "status": "failed",
                        },
                        "container": identity,
                        "evidence": evidence,
                    },
                })
        except Exception as error:
            sys.stderr.write(f"benchmark failed for {container.name}: {error}\n")

    total = sum(counts.values())
    score = max(0, 100 - sum(SEVERITY_WEIGHT[s] * c for s, c in counts.items()) // max(scanned, 1))
    writer.write({
        "event_type": "podman.benchmark.summary",
        "podman": {
            "containers_scanned": scanned,
            "findings": total,
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "score": score,
        },
    })


def collect_inventory(client, writer):
    info = client.info()
    containers = client.containers.list(all=True)
    running = [c for c in containers if c.status == "running"]
    try:
        images = client.images.list()
    except Exception:
        images = []
    try:
        volumes = client.volumes.list()
    except Exception:
        volumes = []
    try:
        networks = client.networks.list()
    except Exception:
        networks = []
    security = info.get("SecurityOptions") or []
    writer.write({
        "event_type": "podman.inventory",
        "podman": {
            "engine": {
                "version": info.get("ServerVersion", ""),
                "rootless": any("rootless" in option for option in security),
                "security_options": security,
                "storage_driver": info.get("Driver", ""),
                "cgroup_version": str(info.get("CgroupVersion", "")),
            },
            "counts": {
                "containers": len(containers),
                "running": len(running),
                "stopped": len(containers) - len(running),
                "images": len(images),
                "volumes": len(volumes),
                "networks": len(networks),
            },
        },
    })


def periodic(client, writer, interval, task, name):
    while True:
        try:
            task(client, writer)
        except Exception as error:
            sys.stderr.write(f"{name} collector error: {error}\n")
        time.sleep(interval)


def event_loop(client, writer):
    while True:
        try:
            stream_events(client, writer)
        except Exception as error:
            sys.stderr.write(f"event stream error: {error}\n")
        time.sleep(5)


def main():
    writer = JsonlWriter(os.path.join(LOG_DIR, "podman.json"))
    client = docker.from_env()

    args = sys.argv[1:]
    if "--once-stats" in args:
        collect_stats(client, writer)
        return
    if "--once-benchmark" in args:
        collect_benchmark(client, writer)
        return
    if "--once-inventory" in args:
        collect_inventory(client, writer)
        return

    threading.Thread(target=event_loop, args=(client, writer), daemon=True).start()
    for interval, task, name in (
        (STATS_INTERVAL, collect_stats, "stats"),
        (BENCH_INTERVAL, collect_benchmark, "benchmark"),
        (INVENTORY_INTERVAL, collect_inventory, "inventory"),
    ):
        threading.Thread(target=periodic, args=(client, writer, interval, task, name),
                         daemon=True).start()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
