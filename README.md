# wazuh-integration-hub

Open source Wazuh integrations. Each integration ships its own collector,
decoders, rules, dashboards and tests, and can be loaded into any Wazuh
manager.

## Contents

```
integrations/podman/    Container lifecycle, resource usage and security benchmark
integrations/network/   Agent-manager bandwidth, retransmissions and latency
```

The rootless Podman deployment of the Wazuh stack used to develop and test the
integrations lives in a separate repository: `wazuh-rootless-podman`.

## Podman container monitoring

Collects container lifecycle events, resource usage and a security benchmark
from the Podman API.

* Lifecycle: create, init, start, stop, die, destroy, exec, kill, oom,
  health_status, plus image, volume and network events
* Metrics: CPU, memory, network, block I/O and PID counters per container
* Benchmark: privileged, host namespaces, runtime socket mounts, capabilities,
  missing limits, writable rootfs, sensitive mounts and more
* Startup and uptime timing derived from the event stream
* Ten visualizations and one dashboard

See `integrations/podman/README.md`.

## Network bandwidth monitoring

Collects host network counters and the TCP sockets used by Wazuh.

* Per-interface throughput and error counters
* Wazuh connection bytes, retransmissions and RTT
* Aggregated agent-manager traffic and rates
* TCP segment and retransmission counters
* ICMP latency to the manager
* Eight visualizations and one dashboard

See `integrations/network/README.md`.

## Loading an integration

Each integration provides a collector, an agent configuration snippet and an
index template. Apply the template before the first alert is indexed, add the
localfile to the agent, and import the dashboard ndjson. The integration
README files contain the exact commands.

Decoders that must run before the built-in JSON decoder are installed under
`ruleset/decoders/` with a prefix that sorts before `0006-json_decoders.xml`
(for example `0005a-podman_decoders.xml`).

## Testing

```
python3 integrations/podman/tests/test_monitoring.py
python3 integrations/network/tests/test_network.py
```

Both suites require a running Wazuh manager container and an enrolled agent on
the same host.

## Roadmap

* Provisioning and attestation for AI agent deployments, including LiteLLM and
  Langfuse observability.
