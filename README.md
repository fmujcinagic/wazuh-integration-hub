# Wazuh Podman & Network Bandwidth Monitoring - Decoders/Rules/Dashboards/Benchmark

Wazuh contribution to integrations in the sense of Podman container lifecycle monitoring and the network bandwidth monitoring.
As of the moment of contributing/writing, Wazuh has no out-of-box (documented) integrations for these needs, eventhough they are highly applicable in today's industry. 

Each integration ships its own collector, decoders, rules, dashboards and tests, and can be loaded into any Wazuh
manager. Please refer to the details in the `network` and `podman` folders for detailed overview and integration of the decoders/rules/dashboards depending on the way you deployed the Wazuh stack.

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

## Future work...

* Provisioning and attestation for AI agent deployments, including LiteLLM and
  Langfuse observability.

## License and credits

This repository is licensed under GPLv2, see `LICENSE`.

Wazuh is developed by Wazuh, Inc. and licensed under GPLv2. This project
integrates with Wazuh, uses the official Wazuh agent container image, and its
agent configuration is based on the Wazuh agent default configuration. Wazuh
is a trademark of Wazuh, Inc. All other code in this repository is original.

