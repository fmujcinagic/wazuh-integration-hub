# Network bandwidth monitoring for Wazuh

Wazuh integration that monitors the network path between agents and managers:
interface throughput, TCP retransmissions, round trip time and latency to the
manager.

## How it works

A collector runs on the monitored host, samples the kernel network counters
and the TCP sockets connected to the Wazuh ports, and writes one JSON document
per line. The Wazuh agent tails that file and forwards the events to the
manager, where custom decoders and rules turn them into alerts. The alerts are
indexed and rendered in the network dashboard.

```
/proc/net/dev, /proc/net/snmp, ss -tin, ping
        |
        v
network_monitor.py  ->  ~/.local/state/wazuh-network/network.json
        |                        |
        |                        v
        |               wazuh-logcollector (agent)
        |                        |
        v                        v
  systemd user service     wazuh-manager -> decoders/rules -> indexer -> dashboard
```

The collector needs `ss` (iproute) and `ping` (iputils).

## Event types

| event_type | Description |
| --- | --- |
| `network.interface` | Per-interface counters and throughput rates from `/proc/net/dev` |
| `network.connection` | Established connections on ports 1514, 1515 and 55000 with bytes, retransmits and RTT from `ss -tin` |
| `network.wazuh` | Aggregated Wazuh traffic: connection count, bytes sent and received, retransmission rate, rates in bits per second |
| `network.snmp` | TCP segment counters and retransmission rate from `/proc/net/snmp` |
| `network.latency` | ICMP round trip time to the manager |

Rates are computed from the delta between consecutive samples.

## Layout

```
scripts/
  network_monitor.py         collector
  network-monitor.service    systemd user unit
  install.sh                 installs and starts the service
agent/
  ossec.conf.snippet         localfile block for the agent
decoders/
  network_decoders.xml       named decoders per event type
rules/
  network_rules.xml          rules 101000-101099
dashboards/
  network_index_template.json  numeric field mappings
  build_dashboards.py          creates the saved objects and exports the ndjson
  network_dashboards.ndjson    index pattern, 8 visualizations, 1 dashboard
tests/
  test_network.py            end-to-end rule and mapping tests
```

## Rules

| ID | Level | Description |
| --- | --- | --- |
| 101000 | 3 | Interface counters |
| 101001 | 5 | Interface receive errors |
| 101002 | 5 | Interface transmit errors |
| 101003 | 3 | Dropped received packets |
| 101004 | 3 | Dropped transmitted packets |
| 101010 | 3 | Wazuh connection |
| 101011 | 5 | Wazuh connection retransmitted bytes |
| 101012 | 7 | Wazuh connection RTT above 100 ms |
| 101020 | 3 | Aggregated Wazuh traffic |
| 101021 | 8 | No active Wazuh connection |
| 101022 | 7 | Wazuh retransmission rate |
| 101023 | 7 | Wazuh uplink above 10 Mbps |
| 101024 | 7 | Wazuh downlink above 10 Mbps |
| 101030 | 3 | TCP segment counters |
| 101031 | 7 | TCP retransmission rate above 10 segments/s |
| 101032 | 5 | TCP receive errors |
| 101040 | 3 | Latency to the manager |
| 101041 | 7 | Latency above 100 ms |
| 101042 | 10 | Latency above 500 ms |

## Install

Install the collector on each monitored host:

```
WAZUH_MANAGER_SERVER=<manager-ip> ./scripts/install.sh
```

This installs `network_monitor.py` under `~/.local/share/wazuh-network/`, a
systemd user service, and starts it. The log is written to
`~/.local/state/wazuh-network/network.json`.

Then add the localfile from `agent/ossec.conf.snippet` to the agent
configuration and mount the log directory at `/var/log/network` in the agent
container. For a containerized agent:

```
podman run ... \
  -v "$HOME/.local/state/wazuh-network":/var/log/network:ro \
  ...
```

Apply the index template and import the dashboard:

```
curl -sk -u admin:SecretPassword -H 'Content-Type: application/json' \
  -X PUT 'https://localhost:9200/_template/network-alerts' \
  --data-binary @dashboards/network_index_template.json

curl -sk -u admin:SecretPassword -H 'osd-xsrf: true' \
  -X POST 'https://localhost:8443/api/saved_objects/_import?overwrite=true' \
  -F 'file=@dashboards/network_dashboards.ndjson'
```

The template is a legacy template with `order: 2`, so it merges with the
`wazuh` template that Filebeat installs. Do not use a composable template, as
any matching composable template disables the legacy `wazuh` mappings.

## Dashboards

`network_dashboards.ndjson` contains an index pattern, eight visualizations
and the `Network Bandwidth Monitoring` dashboard: Wazuh connections, manager
latency, traffic share by interface, TCP retransmission rate, Wazuh traffic
over time, interface throughput, top interfaces and per-connection detail.

## Testing

```
python3 tests/test_network.py
```

The suite checks the collector output, injects controlled events and asserts
that rules 101001, 101011, 101012, 101021, 101022, 101031 and 101042 fire, and
verifies the index mappings and the dashboard saved object.

## Notes

* The collector reports host level counters, so it covers every interface and
  every connection to the manager ports on the host.
* Connections are matched by peer or local port 1514, 1515 or 55000, so both
  the agent side and the manager side of a connection are captured.
* Idle interfaces with no traffic are skipped to keep the event stream small.
