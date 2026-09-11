#!/usr/bin/env python3

import base64
import json
import ssl
import sys
import urllib.request

DASHBOARD_URL = "https://localhost:8443"
CREDENTIALS = "admin:SecretPassword"
INDEX_PATTERN = "podman-alerts"
OUTPUT = "podman_dashboards.ndjson"

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def request(method, path, body=None, raw=False):
    data = None
    headers = {"osd-xsrf": "true"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(DASHBOARD_URL + path, data=data, headers=headers, method=method)
    token = base64.b64encode(CREDENTIALS.encode()).decode()
    req.add_header("Authorization", "Basic " + token)
    with urllib.request.urlopen(req, context=CTX) as response:
        payload = response.read()
        return payload if raw else json.loads(payload or b"{}")


def put_object(kind, object_id, attributes, references=None):
    try:
        request("DELETE", f"/api/saved_objects/{kind}/{object_id}")
    except Exception:
        pass
    body = {"attributes": attributes}
    if references:
        body["references"] = references
    request("POST", f"/api/saved_objects/{kind}/{object_id}", body)
    print(f"created {kind}: {object_id}")


def vis_state(title, vis_type, params, aggs):
    return json.dumps({"title": title, "type": vis_type, "params": params, "aggs": aggs})


def search_source(query):
    return json.dumps({
        "index": INDEX_PATTERN,
        "query": {"query": query, "language": "kuery"},
        "filter": [],
    })


def create_visualization(object_id, title, vis_type, params, aggs, query):
    put_object("visualization", object_id, {
        "title": title,
        "visState": vis_state(title, vis_type, params, aggs),
        "uiStateJSON": "{}",
        "description": "",
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)},
    })


def terms_agg(agg_id, field, size=10, order_by="1", order="desc"):
    return {
        "id": agg_id,
        "enabled": True,
        "type": "terms",
        "schema": "segment",
        "params": {
            "field": field,
            "orderBy": order_by,
            "order": order,
            "size": size,
            "otherBucket": False,
            "otherBucketLabel": "Other",
            "missingBucket": False,
            "missingBucketLabel": "Missing",
        },
    }


def count_agg():
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}


def metric_agg(agg_id, field, metric, label, schema="metric"):
    return {
        "id": agg_id,
        "enabled": True,
        "type": metric,
        "schema": schema,
        "params": {"field": field, "customLabel": label},
    }


PIE_PARAMS = {
    "type": "pie",
    "addTooltip": True,
    "addLegend": True,
    "legendPosition": "right",
    "isDonut": True,
    "labels": {"show": True, "values": True, "last_level": True, "truncate": 100},
}

TABLE_PARAMS = {
    "perPage": 15,
    "showPartialRows": False,
    "showMetricsAtAllLevels": False,
    "sort": {"columnIndex": None, "direction": None},
    "showTotal": False,
    "totalFunc": "sum",
    "percentageCol": "",
}


def main():
    put_object("index-pattern", INDEX_PATTERN, {
        "title": "wazuh-alerts-*",
        "timeFieldName": "@timestamp",
    })

    create_visualization(
        "podman-events-by-action", "Podman: events by action", "pie", PIE_PARAMS,
        [count_agg(), terms_agg("2", "data.podman.action", 15)],
        "rule.groups:podman",
    )

    create_visualization(
        "podman-events-over-time", "Podman: events over time", "histogram",
        {
            "type": "histogram",
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
            "labels": {"show": False},
            "grid": {"categoryLines": False},
            "seriesParams": [{
                "show": True, "type": "histogram", "mode": "stacked",
                "data": {"label": "Count", "id": "1"},
                "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "showCircles": True,
            }],
            "categoryAxes": [{
                "id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
                "style": {}, "scale": {"type": "linear"},
                "labels": {"show": True, "filter": True, "truncate": 100}, "title": {},
            }],
            "valueAxes": [{
                "id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left",
                "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": "Count"},
            }],
        },
        [
            count_agg(),
            {
                "id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
                "params": {"field": "@timestamp", "timeInterval": "auto", "customInterval": "2h",
                           "min_doc_count": 1, "extended_bounds": {}},
            },
            {
                "id": "3", "enabled": True, "type": "terms", "schema": "group",
                "params": {"field": "data.podman.action", "orderBy": "1", "order": "desc",
                           "size": 8, "otherBucket": False, "missingBucket": False},
            },
        ],
        "rule.groups:podman",
    )

    create_visualization(
        "podman-benchmark-by-severity", "Podman: benchmark findings by severity", "pie",
        PIE_PARAMS,
        [count_agg(), terms_agg("2", "data.podman.check.severity", 10)],
        "data.event_type:podman.benchmark",
    )

    create_visualization(
        "podman-benchmark-findings", "Podman: security benchmark findings", "table",
        TABLE_PARAMS,
        [
            count_agg(),
            terms_agg("2", "data.podman.check.id", 20, "1"),
            terms_agg("3", "data.podman.check.title", 20, "1"),
            terms_agg("4", "data.podman.container.name", 20, "1"),
        ],
        "data.event_type:podman.benchmark",
    )

    create_visualization(
        "podman-top-cpu", "Podman: top containers by CPU", "table", TABLE_PARAMS,
        [
            metric_agg("1", "data.podman.cpu_percent", "avg", "Avg CPU %"),
            terms_agg("2", "data.podman.container.name", 20, "1"),
            metric_agg("3", "data.podman.cpu_percent", "max", "Max CPU %"),
        ],
        "data.event_type:podman.stats",
    )

    create_visualization(
        "podman-top-memory", "Podman: top containers by memory", "table", TABLE_PARAMS,
        [
            metric_agg("1", "data.podman.memory_percent", "avg", "Avg memory %"),
            terms_agg("2", "data.podman.container.name", 20, "1"),
            metric_agg("3", "data.podman.memory_used_bytes", "max", "Peak bytes"),
        ],
        "data.event_type:podman.stats",
    )

    create_visualization(
        "podman-container-crashes", "Podman: container crashes", "table", TABLE_PARAMS,
        [
            count_agg(),
            terms_agg("2", "data.podman.container.name", 20, "1"),
            terms_agg("3", "data.podman.exit_code", 20, "1"),
            metric_agg("4", "data.podman.uptime_ms", "max", "Uptime ms"),
        ],
        "data.podman.action:die and data.podman.exit_code > 0",
    )

    create_visualization(
        "podman-running-containers", "Podman: running containers", "metric",
        {
            "addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {
                "percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 100000}],
                "labels": {"show": True}, "invertColors": False,
                "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                          "subText": "", "fontSize": 60},
            },
        },
        [metric_agg("1", "data.podman.counts.running", "max", "Running")],
        "data.event_type:podman.inventory",
    )

    create_visualization(
        "podman-benchmark-score", "Podman: benchmark score", "metric",
        {
            "addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {
                "percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 100}],
                "labels": {"show": True}, "invertColors": False,
                "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                          "subText": "", "fontSize": 60},
            },
        },
        [metric_agg("1", "data.podman.score", "min", "Worst score")],
        "data.event_type:podman.benchmark.summary",
    )

    create_visualization(
        "podman-agents", "Podman: monitored agents", "table", TABLE_PARAMS,
        [count_agg(), terms_agg("2", "agent.name", 20, "1")],
        "rule.groups:podman",
    )

    panels = [
        ("1", "podman-running-containers", 0, 0, 12, 12),
        ("2", "podman-benchmark-score", 12, 0, 12, 12),
        ("3", "podman-events-by-action", 24, 0, 12, 12),
        ("4", "podman-benchmark-by-severity", 36, 0, 12, 12),
        ("5", "podman-events-over-time", 0, 12, 24, 15),
        ("6", "podman-agents", 24, 12, 24, 15),
        ("7", "podman-top-cpu", 0, 27, 24, 15),
        ("8", "podman-top-memory", 24, 27, 24, 15),
        ("9", "podman-benchmark-findings", 0, 42, 24, 15),
        ("10", "podman-container-crashes", 24, 42, 24, 15),
    ]
    panels_json = json.dumps([
        {
            "version": "2.19.5",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_id},
            "panelIndex": panel_id,
            "embeddableConfig": {},
            "panelRefName": f"panel_{panel_id}",
        }
        for panel_id, _vis, x, y, w, h in panels
    ])
    references = [
        {"name": f"panel_{panel_id}", "type": "visualization", "id": vis_id}
        for panel_id, vis_id, *_ in panels
    ]
    put_object("dashboard", "podman-overview", {
        "title": "Podman Container Monitoring",
        "hits": 0,
        "description": "Lifecycle events, resource usage and security benchmark for Podman containers.",
        "panelsJSON": panels_json,
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False, "darkTheme": False}),
        "version": 1,
        "timeRestore": False,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "query": {"query": "rule.groups:podman", "language": "kuery"},
                "filter": [],
            }),
        },
    }, references)

    export = request("POST", "/api/saved_objects/_export", {
        "objects": [
            {"type": "index-pattern", "id": INDEX_PATTERN},
            {"type": "visualization", "id": "podman-events-by-action"},
            {"type": "visualization", "id": "podman-events-over-time"},
            {"type": "visualization", "id": "podman-benchmark-by-severity"},
            {"type": "visualization", "id": "podman-benchmark-findings"},
            {"type": "visualization", "id": "podman-top-cpu"},
            {"type": "visualization", "id": "podman-top-memory"},
            {"type": "visualization", "id": "podman-container-crashes"},
            {"type": "visualization", "id": "podman-running-containers"},
            {"type": "visualization", "id": "podman-benchmark-score"},
            {"type": "visualization", "id": "podman-agents"},
            {"type": "dashboard", "id": "podman-overview"},
        ],
        "includeReferencesDeep": True,
    }, raw=True)

    with open(OUTPUT, "wb") as handle:
        handle.write(export)
    print(f"exported {len(export.splitlines())} saved objects to {OUTPUT}")


if __name__ == "__main__":
    sys.exit(main())
