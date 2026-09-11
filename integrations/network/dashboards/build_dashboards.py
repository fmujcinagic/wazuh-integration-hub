#!/usr/bin/env python3

import base64
import json
import ssl
import sys
import urllib.request

DASHBOARD_URL = "https://localhost:8443"
CREDENTIALS = "admin:SecretPassword"
INDEX_PATTERN = "network-alerts"
OUTPUT = "network_dashboards.ndjson"

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
    req.add_header("Authorization", "Basic " + base64.b64encode(CREDENTIALS.encode()).decode())
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


def search_source(query):
    return json.dumps({
        "index": INDEX_PATTERN,
        "query": {"query": query, "language": "kuery"},
        "filter": [],
    })


def create_visualization(object_id, title, vis_type, params, aggs, query):
    put_object("visualization", object_id, {
        "title": title,
        "visState": json.dumps({"title": title, "type": vis_type, "params": params, "aggs": aggs}),
        "uiStateJSON": "{}",
        "description": "",
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)},
    })


def count_agg():
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}


def terms_agg(agg_id, field, size=15, order_by="1", order="desc", schema="segment"):
    return {
        "id": agg_id, "enabled": True, "type": "terms", "schema": schema,
        "params": {"field": field, "orderBy": order_by, "order": order, "size": size,
                   "otherBucket": False, "otherBucketLabel": "Other",
                   "missingBucket": False, "missingBucketLabel": "Missing"},
    }


def metric_agg(agg_id, field, metric, label, schema="metric"):
    return {"id": agg_id, "enabled": True, "type": metric, "schema": schema,
            "params": {"field": field, "customLabel": label}}


def date_histogram():
    return {
        "id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
        "params": {"field": "@timestamp", "timeInterval": "auto", "customInterval": "2h",
                   "min_doc_count": 1, "extended_bounds": {}},
    }


PIE_PARAMS = {
    "type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
    "isDonut": True, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100},
}

TABLE_PARAMS = {
    "perPage": 15, "showPartialRows": False, "showMetricsAtAllLevels": False,
    "sort": {"columnIndex": None, "direction": None}, "showTotal": False,
    "totalFunc": "sum", "percentageCol": "",
}

LINE_PARAMS = {
    "type": "line", "addTooltip": True, "addLegend": True, "legendPosition": "right",
    "times": [], "addTimeMarker": False, "labels": {"show": False},
    "grid": {"categoryLines": False},
    "seriesParams": [{
        "show": True, "type": "line", "mode": "normal",
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
        "title": {"text": "Value"},
    }],
}


def metric_params(label):
    return {
        "addTooltip": True, "addLegend": False, "type": "metric",
        "metric": {
            "percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
            "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 1000000000}],
            "labels": {"show": True}, "invertColors": False,
            "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                      "subText": label, "fontSize": 60},
        },
    }


def main():
    put_object("index-pattern", INDEX_PATTERN, {
        "title": "wazuh-alerts-*",
        "timeFieldName": "@timestamp",
    })

    create_visualization(
        "network-wazuh-connections", "Network: Wazuh connections", "metric",
        metric_params("Connections"),
        [metric_agg("1", "data.network.connections", "max", "Connections")],
        "data.event_type:network.wazuh",
    )

    create_visualization(
        "network-latency", "Network: manager latency", "metric",
        metric_params("ms"),
        [metric_agg("1", "data.network.rtt_ms", "max", "RTT ms")],
        "data.event_type:network.latency",
    )

    create_visualization(
        "network-wazuh-traffic", "Network: Wazuh traffic", "line", LINE_PARAMS,
        [
            metric_agg("1", "data.network.rate_sent_bps", "avg", "Sent bps"),
            date_histogram(),
            metric_agg("3", "data.network.rate_received_bps", "avg", "Received bps"),
        ],
        "data.event_type:network.wazuh",
    )

    create_visualization(
        "network-interface-throughput", "Network: interface throughput", "line", LINE_PARAMS,
        [
            metric_agg("1", "data.network.rx_rate_bps", "avg", "RX bps"),
            date_histogram(),
            metric_agg("3", "data.network.tx_rate_bps", "avg", "TX bps"),
            terms_agg("4", "data.network.interface", 5, "1", "desc", "group"),
        ],
        "data.event_type:network.interface",
    )

    create_visualization(
        "network-top-interfaces", "Network: top interfaces", "table", TABLE_PARAMS,
        [
            metric_agg("1", "data.network.rx_rate_bps", "avg", "Avg RX bps"),
            terms_agg("2", "data.network.interface", 15, "1"),
            metric_agg("3", "data.network.tx_rate_bps", "avg", "Avg TX bps"),
            metric_agg("4", "data.network.rx_errors", "max", "RX errors"),
        ],
        "data.event_type:network.interface",
    )

    create_visualization(
        "network-traffic-by-interface", "Network: traffic share by interface", "pie", PIE_PARAMS,
        [metric_agg("1", "data.network.rx_rate_bps", "sum", "RX bps"), terms_agg("2", "data.network.interface", 15)],
        "data.event_type:network.interface",
    )

    create_visualization(
        "network-connections", "Network: Wazuh connections", "table", TABLE_PARAMS,
        [
            metric_agg("1", "data.network.rtt_ms", "max", "RTT ms"),
            terms_agg("2", "data.network.peer", 15, "1"),
            metric_agg("3", "data.network.bytes_sent", "max", "Bytes sent"),
            metric_agg("4", "data.network.bytes_retrans", "max", "Bytes retrans"),
        ],
        "data.event_type:network.connection",
    )

    create_visualization(
        "network-retrans", "Network: TCP retransmission rate", "line", LINE_PARAMS,
        [
            metric_agg("1", "data.network.retrans_rate", "avg", "Retrans/s"),
            date_histogram(),
        ],
        "data.event_type:network.snmp",
    )

    panels = [
        ("1", "network-wazuh-connections", 0, 0, 12, 12),
        ("2", "network-latency", 12, 0, 12, 12),
        ("3", "network-traffic-by-interface", 24, 0, 12, 12),
        ("4", "network-retrans", 36, 0, 12, 12),
        ("5", "network-wazuh-traffic", 0, 12, 24, 15),
        ("6", "network-interface-throughput", 24, 12, 24, 15),
        ("7", "network-top-interfaces", 0, 27, 24, 15),
        ("8", "network-connections", 24, 27, 24, 15),
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
    put_object("dashboard", "network-overview", {
        "title": "Network Bandwidth Monitoring",
        "hits": 0,
        "description": "Agent-manager bandwidth, retransmissions and latency.",
        "panelsJSON": panels_json,
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False, "darkTheme": False}),
        "version": 1,
        "timeRestore": False,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "query": {"query": "rule.groups:network", "language": "kuery"},
                "filter": [],
            }),
        },
    }, references)

    objects = [{"type": "index-pattern", "id": INDEX_PATTERN}]
    objects += [{"type": "visualization", "id": vis_id} for _, vis_id, *_ in panels]
    objects.append({"type": "dashboard", "id": "network-overview"})
    export = request("POST", "/api/saved_objects/_export",
                     {"objects": objects, "includeReferencesDeep": True}, raw=True)
    with open(OUTPUT, "wb") as handle:
        handle.write(export)
    print(f"exported {len(export.splitlines())} saved objects to {OUTPUT}")


if __name__ == "__main__":
    sys.exit(main())
