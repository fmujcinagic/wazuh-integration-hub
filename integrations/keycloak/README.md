# Keycloak authentication monitoring for Wazuh

Wazuh integration that watches Keycloak identity flows: logins, login
failures with their Keycloak error reasons, user enumeration, brute force
protection, disabled accounts and admin operations on users and realms.

## How it works

Keycloak emits its authentication events into the server log through the
**built-in jboss-logging event listener** - no custom SPI is required. The
listener is enabled per realm through the admin REST API or the console
(realm settings, events, add the `jboss-logging` provider). The events then
appear as statements inside the Quarkus console lines:

```
WARN  [org.keycloak.events] (executor-thread-1) type="LOGIN", realmId="11bb...", realmName="master", clientId="admin-cli", userId="...", ipAddress="192.168.1.40"
WARN  [org.keycloak.events] (executor-thread-1) type="LOGIN_ERROR", realmId="...", realmName="master", clientId="account", userId="null", ipAddress="192.168.1.40", error="invalid_grant", username="alice"
```

Admin operations (users, roles and realms) emit a second statement shape:

```
WARN  [org.keycloak.events] (executor-thread-1) operationType="CREATE", realmId="...", resourceType="USER", resourcePath="users/11bb..."
```

The Keycloak container writes its console to a file on the monitored host,
the Wazuh agent tails it and the decoders turn each statement into alert
fields. The localfile uses `log_format syslog`, not `json`: the statements
are plain console text, so a json localfile would drop every one of them.

```
keycloak container console
        |
        v
keycloak.json (the collector is the server log itself)
        |
        v
wazuh-logcollector (agent, syslog format)
        |
        v
wazuh-manager -> decoders/rules -> indexer -> dashboard
```

A second, optional path accepts canonical JSON payloads (`event_type:
keycloak.login` / `keycloak.admin`) from a collector or an SPI listener. Both
paths land in the same `data.keycloak.*` fields and produce the same alerts,
so a deployment can switch between them without touching its rules.

## Deployment

See the [wazuh-rootless-podman README](https://github.com/fmujcinagic/wazuh-rootless-podman)
for the containerized variant: the `hub_integrations` playbook role stages
the decoders and rules into **every** manager node (master and workers)
through a Quadlet drop-in, mounts the keycloak log directory into the agent
container and imports the index template plus dashboards on the master. No
collector daemon is needed.

For a native Wazuh deployment copy the decoder and rule files into
`/var/ossec/ruleset/decoders/0005c-keycloak_decoders.xml` and
`/var/ossec/etc/rules/keycloak_rules.xml`, restart `wazuh-manager` and add
the localfile from `snippets/ossec.conf` to the agent configuration.

## Decoders

| Decoder | Applies to |
| --- | --- |
| `keycloak-events` | jboss-logging statements (`type=...` and `operationType=...`) |
| `keycloak-login` | canonical JSON payloads with `event_type:keycloak.login` |
| `keycloak-admin-events` | canonical JSON payloads with `event_type:keycloak.admin` |

The listener chain starts with a prematch on the logger line and extracts
every field with a sibling decoder, so a login without a client, or an admin
statement without a realm, still decodes the fields that are present.

The decoded fields live under `data.keycloak.*`: `type`, `realm`, `user`,
`client`, `ip`, `error`, `operation`, `resource_type` and `resource`.

## Rules

The listener and canonical paths decode to different decoder names, so each
path has its own numbered rules with identical semantics.

| Listener | Canonical | Level | Description |
| --- | --- | --- | --- |
| 102000 | 102010 | 3 | Successful login |
| 102001 | 102011 | 5 | Login failure |
| 102002 | 102012 | 7 | Rejected credentials (invalid_grant, INVALID_USER_CREDENTIALS) |
| 102003 | 102013 | 5 | Unknown user attempted a login (user enumeration) |
| 102004 | 102014 | 10 | Brute force protection triggered |
| 102005 | 102015 | 6 | Disabled user attempted a login |
| 102006 | 102016 | 3 | Logout |
| 102021 | 102020 | 8 | Admin operation on a user, role or realm |

## Dashboards

`keycloak_dashboards.ndjson` contains an index pattern, six visualizations
and the `Keycloak Authentication Monitoring` dashboard: login trends,
failures by error, top users, failed sources, the successful login metric
and brute force findings.

## Screenshots

![Keycloak dashboard](../../screenshots/keycloak-dashboard.png)

![Keycloak alerts](../../screenshots/keycloak-alerts.png)

## Testing

```
python3 integrations/keycloak/tests/test_keycloak.py
```

The suite spawns a disposable Keycloak container, enables the jboss-logging
event listener through the admin API, drives a successful login plus login
failures through the token endpoint, verifies the events land in the
keycloak log, injects a login failure through the agent and asserts that the
listener rule 102003 fires, then injects canonical payloads and asserts that
rules 102010, 102013 and 102012 fire. Finally it checks the index mapping
and the dashboard saved object. Point `WAZUH_INDEXER_URL` and
`WAZUH_DASHBOARD_URL` at the master when running it on a worker node.
