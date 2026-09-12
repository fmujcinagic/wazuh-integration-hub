# Podman container monitoring for Wazuh

Out-of-the-box Wazuh integration that monitors Podman containers: lifecycle
events, resource usage and a security benchmark, with decoders, rules, an
index template and a dashboard.

## How it works

Podman exposes a Docker-compatible API on its user socket. A collector runs as
a systemd user service on the monitored host, talks to that API and writes one
JSON document per line to a local log file. The Wazuh agent tails the file and
forwards each event to the manager, where custom decoders and rules turn them
into alerts. The alerts are indexed and rendered in the Podman dashboard.

```
podman API (unix socket)
        |
        v
podman_monitor.py  ->  ~/.local/state/wazuh-podman/podman.json
        |                        |
        |                        v
        |               wazuh-logcollector (agent)
        |                        |
        v                        v
   (security checks)      wazuh-manager  ->  decoders/rules  ->  indexer  ->  dashboard
```

The collector emits five event types:

| event_type | Description |
| --- | --- |
| `podman.event` | Container lifecycle: create, init, start, stop, die, destroy, exec, exec_died, kill, oom, health_status, plus image, volume and network events |
| `podman.stats` | Per-container CPU, memory, network, block I/O and PID counters |
| `podman.benchmark` | One document per failed security check |
| `podman.benchmark.summary` | Aggregate score and finding counts per scan |
| `podman.inventory` | Engine version, rootless flag, container/image/volume/network counts |

## Layout

```
scripts/
  podman_monitor.py          collector
  podman-monitor.service     systemd user unit
  install.sh                 installs and starts the collector
snippets/
  ossec.conf                 localfile block for the agent
decoders/
  podman_decoders.xml        named decoders per event type
rules/
  podman_rules.xml           rules 100100-100199
dashboards/
  podman_index_template.json numeric field mappings for wazuh-alerts-*
  build_dashboards.py        creates the saved objects and exports the ndjson
  podman_dashboards.ndjson   index pattern, 10 visualizations, 1 dashboard
tests/
  test_monitoring.py         end-to-end scenario and rule test suite
```

## Decoders

The collector writes compact JSON, so the decoders pin each `event_type` to a
named decoder and let the JSON decoder extract every field:

* `podman-event`
* `podman-stats`
* `podman-benchmark`
* `podman-benchmark-summary`
* `podman-inventory`

The file is installed as `ruleset/decoders/0005a-podman_decoders.xml` so it is
evaluated before the generic JSON decoder and the `decoded_as` names take
effect. All payload fields live under a `podman` object to avoid collisions
with reserved Wazuh fields such as `action`, `type` and `status`.

## Rules

| ID | Level | Description |
| --- | --- | --- |
| 100100 | 3 | Container created |
| 100101 | 3 | Container started (reports startup time) |
| 100102 | 3 | Container stopped (reports uptime) |
| 100103 | 5 | Container destroyed |
| 100104 | 7 | Container died |
| 100105 | 10 | Container exited with a non-zero code |
| 100106 | 12 | Container killed with SIGKILL (exit 137) |
| 100107 | 10 | Container out of memory |
| 100108 | 5 | Container received SIGKILL |
| 100109 | 3 | Container restarted |
| 100110 | 8 | Command executed in a container |
| 100112 | 3 | Container paused, unpaused or initialized |
| 100113 | 3 | Container health status changed |
| 100114 | 3 | Image event |
| 100115 | 3 | Volume event |
| 100116 | 4 | Network connect or disconnect |
| 100120 | 3 | Resource statistics sample |
| 100121 | 7 | CPU usage above 80 percent |
| 100122 | 7 | Memory usage above 80 percent |
| 100123 | 10 | Memory usage above 95 percent |
| 100130 | 3 | Benchmark finding, low |
| 100131 | 7 | Benchmark finding, medium |
| 100132 | 10 | Benchmark finding, high |
| 100133 | 13 | Benchmark finding, critical |
| 100134 | 3 | Benchmark summary |
| 100135 | 7 | Benchmark score below 70 |
| 100136 | 10 | Container healthcheck failing |
| 100140 | 3 | Inventory snapshot |

## Security benchmark

Every scan inspects each container and reports these checks:

| ID | Severity | Check |
| --- | --- | --- |
| PODMAN-001 | medium | Container runs as root |
| PODMAN-002 | critical | Privileged container |
| PODMAN-003 | high | Host network namespace |
| PODMAN-004 | high | Host PID namespace |
| PODMAN-005 | medium | Host IPC namespace |
| PODMAN-006 | critical | Container runtime socket mounted |
| PODMAN-007 | medium | No CPU or memory limits |
| PODMAN-008 | high | Added Linux capabilities |
| PODMAN-009 | low | Writable root filesystem |
| PODMAN-010 | medium | no-new-privileges not set |
| PODMAN-011 | high | Sensitive host path mounted |
| PODMAN-012 | medium | No AppArmor or SELinux profile |
| PODMAN-014 | low | Floating image tag |
| PODMAN-015 | high | Container was OOM killed |
| PODMAN-016 | high | Healthcheck failing |

The summary score is `100 - weighted findings / containers scanned`, where the
weights are critical 10, high 7, medium 4 and low 1.

## Dashboards

`podman_dashboards.ndjson` contains an index pattern, ten visualizations and
the `Podman Container Monitoring` dashboard:

* running containers and worst benchmark score (metrics)
* events by action and events over time
* benchmark findings by severity
* top containers by CPU and by memory
* benchmark findings table and container crash table
* monitored agents

Import it from Dashboard Management > Saved Objects > Import, or apply it
with the API:

```
curl -sk -u admin:SecurePassword -H 'osd-xsrf: true' \
  -X POST 'https://localhost:8443/api/saved_objects/_import?overwrite=true' \
  -F 'file=@podman_dashboards.ndjson'
```

The numeric fields are mapped by `podman_index_template.json`. It is applied
as a legacy index template with a higher order than the `wazuh` template that
Filebeat installs, so the two merge instead of replacing each other. A
composable template must not be used here: any matching composable template
takes precedence and disables the legacy `wazuh` template, which would leave
fields such as `agent.name` and `manager.name` dynamically mapped as text.

```
curl -sk -u admin:SecurePassword -H 'Content-Type: application/json' \
  -X PUT 'https://localhost:9200/_template/podman-alerts' \
  --data-binary @podman_index_template.json
```

Apply it before the first alert is indexed, or delete the current daily
`wazuh-alerts-*` index afterwards so it is recreated with the merged mappings.

`build_dashboards.py` recreates and re-exports the saved objects when the
visualizations change.

## Collector

The collector runs as a systemd user service on the monitored host, talks to
the Podman API and writes JSONL to `~/.local/state/wazuh-podman/podman.json`.
It needs the Podman socket and the `docker` Python package.

```
./scripts/install.sh
```

The script creates a virtual environment with the `docker` package, installs
the service, enables `podman.socket` and starts the collector. To remove it:

```
systemctl --user disable --now podman-monitor.service
```

## Containerized agent

A running Wazuh agent is assumed. Add the localfile from `snippets/ossec.conf`
to the agent configuration and mount the monitor log directory at
`/var/log/podman` in the agent container:

```
podman run ... \
  -v "$HOME/.local/state/wazuh-podman":/var/log/podman:ro \
  ...
```

The agent joins the `podman` group. Create the group on the manager first if it
does not exist.

## Standard Wazuh deployment

The integration works with any Wazuh manager and agent, including a native
installation running as systemd services.

### Manager

Copy the decoder and the rules, then restart the manager:

```
sudo install -m 0640 -o root -g wazuh \
  decoders/podman_decoders.xml /var/ossec/ruleset/decoders/0005a-podman_decoders.xml
sudo install -m 0640 -o root -g wazuh \
  rules/podman_rules.xml /var/ossec/etc/rules/podman_rules.xml
sudo systemctl restart wazuh-manager
```

The decoder is installed under `ruleset/decoders/` with a `0005a-` prefix so it
is read before `0006-json_decoders.xml`. If it is placed in `etc/decoders/`
instead, the generic JSON decoder matches first and the `decoded_as` names do
not take effect.

Verify with a sample event:

```
echo '{"event_type":"podman.stats","podman":{"container":{"name":"test"},"cpu_percent":1}}' \
  | sudo /var/ossec/bin/wazuh-logtest
```

### Agent

Add the localfile from `snippets/ossec.conf` to `/var/ossec/etc/ossec.conf`.
A native agent reads the collector log directly, so set the location to the
collector state file:

```
<localfile>
  <log_format>json</log_format>
  <location>/home/<user>/.local/state/wazuh-podman/podman.json</location>
</localfile>
```

Then restart the agent:

```
sudo systemctl restart wazuh-agent
```

### Indexer and dashboard

Apply the index template and import the dashboard as shown in the Dashboards
section. The indexer listens on 9200 and the dashboard on 443 or 8443
depending on the deployment.

## Testing

`tests/test_monitoring.py` runs containers, breaks them and asserts that the
expected rules fire. It needs a running manager container and an enrolled
agent on the same host.

```
python3 tests/test_monitoring.py
```

The suite covers container create/start/stop, abnormal exit, SIGKILL, OOM,
command execution, unhealthy containers, the privileged, host-network,
sensitive-mount, missing-limits and floating-tag benchmark checks, CPU and
memory measurements, indexer coverage and the dashboard saved object.

## Notes

* The collector talks to the Podman API directly, so no Docker daemon or
  docker-listener wodle is involved.
* Podman health events do not carry the health state, so the healthcheck check
  is evaluated from the container inspect data during each benchmark scan.
* Podman exec events do not include the executed command, so shell detection is
  not possible from the event stream alone.
