#!/usr/bin/env python3
import os

import base64
import json
import ssl
import sys
import urllib.request

DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "https://localhost:8443")
CREDENTIALS = os.environ.get("WAZUH_CREDENTIALS", "admin:SecretPassword")
INDEX_PATTERN = "keycloak-alerts"
OUTPUT = "keycloak_dashboards.ndjson"

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


def top_hits_agg(agg_id, field, label, schema="metric"):
    return {"id": agg_id, "enabled": True, "type": "top_hits", "schema": schema,
            "params": {"field": field, "aggregate": "concat", "size": 1,
                       "sortField": "@timestamp", "sortOrder": "desc", "customLabel": label}}


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
        "title": {"text": "Count"},
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
        "keycloak-login-trends", "Keycloak: logins over time", "line", LINE_PARAMS,
        [count_agg(), date_histogram()],
        "rule.groups:keycloak_login",
    )

    create_visualization(
        "keycloak-failures-by-error", "Keycloak: login failures by error", "pie", PIE_PARAMS,
        [count_agg(), terms_agg("2", "data.keycloak.error", 15)],
        "data.event_type:keycloak.login AND data.keycloak.type:LOGIN_ERROR",
    )

    create_visualization(
        "keycloak-top-users", "Keycloak: top users", "table", TABLE_PARAMS,
        [
            count_agg(),
            terms_agg("2", "data.keycloak.user", 15, "1"),
            terms_agg("3", "data.keycloak.realm", 5, "1"),
            top_hits_agg("4", "data.keycloak.ip", "Last IP"),
        ],
        "data.event_type:keycloak.login",
    )

    create_visualization(
        "keycloak-failed-by-ip", "Keycloak: failed logins by source", "table", TABLE_PARAMS,
        [
            count_agg(),
            terms_agg("2", "data.keycloak.ip", 15, "1"),
            top_hits_agg("3", "data.keycloak.ip", "Last IP"),
            terms_agg("4", "data.keycloak.error", 5, "1"),
        ],
        "data.keycloak.type:LOGIN_ERROR",
    )

    create_visualization(
        "keycloak-success-logins", "Keycloak: successful logins", "metric", metric_params("Logins"),
        [count_agg()],
        "data.keycloak.type:LOGIN",
    )

    create_visualization(
        "keycloak-bruteforce", "Keycloak: brute force findings", "table", TABLE_PARAMS,
        [count_agg(), terms_agg("2", "data.keycloak.user", 10, "1"), terms_agg("3", "data.keycloak.ip", 5, "1")],
        "rule.groups:keycloak_bruteforce",
    )

    panels = [
        ("1", "keycloak-success-logins", 0, 0, 12, 12),
        ("2", "keycloak-bruteforce", 12, 0, 12, 12),
        ("3", "keycloak-failures-by-error", 24, 0, 12, 12),
        ("4", "keycloak-top-users", 36, 0, 12, 12),
        ("5", "keycloak-login-trends", 0, 12, 24, 15),
        ("6", "keycloak-failed-by-ip", 24, 12, 24, 15),
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
    put_object("dashboard", "keycloak-overview", {
        "title": "Keycloak Authentication Monitoring",
        "hits": 0,
        "description": "Logins, login failures, brute force findings and admin operations.",
        "panelsJSON": panels_json,
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False, "darkTheme": False}),
        "version": 1,
        "timeRestore": False,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "query": {"query": "rule.groups:keycloak", "language": "kuery"},
                "filter": [],
            }),
        },
    }, references)

    objects = [{"type": "index-pattern", "id": INDEX_PATTERN}]
    objects += [{"type": "visualization", "id": vis_id} for _, vis_id, *_ in panels]
    objects.append({"type": "dashboard", "id": "keycloak-overview"})
    export = request("POST", "/api/saved_objects/_export",
                     {"objects": objects, "includeReferencesDeep": True}, raw=True)
    lines = [line for line in export.splitlines() if b'"exportedCount"' not in line]
    with open(OUTPUT, "wb") as handle:
        handle.write(b"\n".join(lines) + b"\n")
    print(f"exported {len(lines)} saved objects to {OUTPUT}")


if __name__ == "__main__":
    sys.exit(main())
