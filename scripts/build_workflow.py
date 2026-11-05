#!/usr/bin/env python3
"""Build workflows/wazuh-ai-triage.json from workflows/src/.

The JavaScript of every Code node lives in workflows/src/wazuh-ai-triage/*.js, so it
can be read, reviewed and unit-tested like normal code (tests/js/). This script puts
that code into the n8n export, together with the node layout below. The output is
deterministic: the same sources always give the same file.

    python3 scripts/build_workflow.py          # rewrite the workflow file
    python3 scripts/build_workflow.py --check  # fail if the file is out of date (CI)

Edit the .js files or this script, never the generated JSON by hand.
"""
import json
import pathlib
import sys
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "workflows" / "src" / "wazuh-ai-triage"
OUT = ROOT / "workflows" / "wazuh-ai-triage.json"
NAMESPACE = uuid.UUID("6f1d2a8e-3c4b-5d6e-8f90-a1b2c3d4e5f6")

STICKY = """## Wazuh AI Triage
Wazuh alert -> sanitize -> acknowledge -> dedup -> AbuseIPDB -> local LLM -> schema check -> priority -> Telegram.

All settings come from environment variables (see `.env.example`).
Code nodes are generated from `workflows/src/` by `scripts/build_workflow.py`.
Auto-block is **dry-run only** in this version."""


def node_id(name):
    return str(uuid.uuid5(NAMESPACE, name))


def code(name, file, position, mode=None):
    params = {"jsCode": (SRC / file).read_text(encoding="utf-8")}
    if mode:
        params = {"mode": mode, **params}
    return {"name": name, "type": "n8n-nodes-base.code", "typeVersion": 2, "position": position, "parameters": params}


def if_node(name, position, left, operator, right=""):
    return {
        "name": name,
        "type": "n8n-nodes-base.if",
        "typeVersion": 2,
        "position": position,
        "parameters": {
            "conditions": {
                "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict"},
                "conditions": [
                    {"id": node_id(name + ":condition"), "leftValue": left, "rightValue": right, "operator": operator}
                ],
                "combinator": "and",
            },
            "options": {},
        },
    }


IS_TRUE = {"type": "boolean", "operation": "true", "singleValue": True}

NODES = [
    {
        "name": "About",
        "type": "n8n-nodes-base.stickyNote",
        "typeVersion": 1,
        "position": [0, 0],
        "parameters": {"content": STICKY, "height": 220, "width": 520},
    },
    {
        "name": "Wazuh Webhook",
        "type": "n8n-nodes-base.webhook",
        "typeVersion": 2,
        "position": [0, 300],
        "webhookId": "d73bb8e4-e1f4-555d-9091-da95ec5f2ef9",
        "parameters": {"httpMethod": "POST", "path": "wazuh-alert", "responseMode": "responseNode", "options": {}},
    },
    code("Sanitize & Validate", "sanitize-validate.js", [220, 300]),
    {
        # Answers the HTTP request right away: 202 accepted, 400 bad input, 401 wrong
        # secret, 503 not configured. The analysis continues after the answer.
        "name": "Acknowledge",
        "type": "n8n-nodes-base.respondToWebhook",
        "typeVersion": 1.1,
        "position": [440, 300],
        "parameters": {
            "respondWith": "json",
            "responseBody": "={{ JSON.stringify($json.http_body) }}",
            "options": {"responseCode": "={{ $json.http_status }}"},
        },
    },
    if_node("Accepted?", [660, 300], "={{ $json.accepted }}", IS_TRUE),
    code("Deduplicate", "deduplicate.js", [880, 300]),
    if_node("Public IP + API key?", [1100, 300], "={{ $json.enrich }}", IS_TRUE),
    {
        "name": "AbuseIPDB Lookup",
        "type": "n8n-nodes-base.httpRequest",
        "typeVersion": 4.2,
        "position": [1320, 160],
        "onError": "continueRegularOutput",
        "parameters": {
            "url": "={{ $env.ABUSEIPDB_API_URL || 'https://api.abuseipdb.com/api/v2/check' }}",
            "sendQuery": True,
            "queryParameters": {
                "parameters": [
                    {"name": "ipAddress", "value": "={{ $json.srcip }}"},
                    {"name": "maxAgeInDays", "value": "90"},
                ]
            },
            "sendHeaders": True,
            "headerParameters": {
                "parameters": [
                    {"name": "Key", "value": "={{ $env.ABUSEIPDB_API_KEY }}"},
                    {"name": "Accept", "value": "application/json"},
                ]
            },
            "options": {"timeout": 15000},
        },
    },
    code("Attach Threat Intel", "attach-threat-intel.js", [1540, 160], mode="runOnceForEachItem"),
    code("Build LLM Request", "build-llm-request.js", [1760, 300], mode="runOnceForEachItem"),
    {
        "name": "LLM Triage",
        "type": "n8n-nodes-base.httpRequest",
        "typeVersion": 4.2,
        "position": [1980, 300],
        "onError": "continueRegularOutput",
        "parameters": {
            "method": "POST",
            "url": "={{ ($env.LLM_BASE_URL || 'http://host.docker.internal:1234/v1').replace(/\\/+$/, '') }}/chat/completions",
            "sendHeaders": True,
            "headerParameters": {
                "parameters": [{"name": "Authorization", "value": "=Bearer {{ $env.LLM_API_KEY || 'local' }}"}]
            },
            "sendBody": True,
            "specifyBody": "json",
            "jsonBody": "={{ JSON.stringify($json.llm_request) }}",
            "options": {"timeout": 300000},
        },
    },
    code("Parse & Score", "parse-score.js", [2200, 300], mode="runOnceForEachItem"),
    if_node(
        "Telegram enabled?",
        [2420, 300],
        "={{ String($env.TELEGRAM_ENABLED ?? 'true').trim().toLowerCase() }}",
        {"type": "string", "operation": "notEquals"},
        "false",
    ),
    {
        # Retries 3 times, 5 s apart. If it still fails, "Result" fails the execution.
        "name": "Send Telegram",
        "type": "n8n-nodes-base.httpRequest",
        "typeVersion": 4.2,
        "position": [2640, 200],
        "onError": "continueRegularOutput",
        "retryOnFail": True,
        "maxTries": 3,
        "waitBetweenTries": 5000,
        "parameters": {
            "method": "POST",
            "url": "={{ $env.TELEGRAM_API_BASE || 'https://api.telegram.org' }}/bot{{ $env.TELEGRAM_BOT_TOKEN }}/sendMessage",
            "sendBody": True,
            "specifyBody": "json",
            "jsonBody": "={{ JSON.stringify({ chat_id: $env.TELEGRAM_CHAT_ID, text: $json.message, disable_web_page_preview: true }) }}",
            "options": {"timeout": 15000},
        },
    },
    code("Result", "result.js", [2860, 300], mode="runOnceForEachItem"),
]

EDGES = [
    ("Wazuh Webhook", 0, "Sanitize & Validate"),
    ("Sanitize & Validate", 0, "Acknowledge"),
    ("Acknowledge", 0, "Accepted?"),
    ("Accepted?", 0, "Deduplicate"),
    ("Deduplicate", 0, "Public IP + API key?"),
    ("Public IP + API key?", 0, "AbuseIPDB Lookup"),
    ("Public IP + API key?", 1, "Build LLM Request"),
    ("AbuseIPDB Lookup", 0, "Attach Threat Intel"),
    ("Attach Threat Intel", 0, "Build LLM Request"),
    ("Build LLM Request", 0, "LLM Triage"),
    ("LLM Triage", 0, "Parse & Score"),
    ("Parse & Score", 0, "Telegram enabled?"),
    ("Telegram enabled?", 0, "Send Telegram"),
    ("Telegram enabled?", 1, "Result"),
    ("Send Telegram", 0, "Result"),
]


def build():
    nodes = []
    for spec in NODES:
        node = {"parameters": spec["parameters"], "id": node_id(spec["name"])}
        node.update({k: v for k, v in spec.items() if k != "parameters"})
        nodes.append(node)
    connections = {}
    for source, output, target in EDGES:
        outputs = connections.setdefault(source, {"main": []})["main"]
        while len(outputs) <= output:
            outputs.append([])
        outputs[output].append({"node": target, "type": "main", "index": 0})
    workflow = {
        "name": "Wazuh AI Triage",
        "nodes": nodes,
        "connections": connections,
        "settings": {"executionOrder": "v1"},
        "pinData": {},
        "meta": {"templateCredsSetupCompleted": True},
        "tags": [],
    }
    return json.dumps(workflow, indent=2, ensure_ascii=False) + "\n"


def main(argv):
    text = build()
    if "--check" in argv:
        if OUT.read_text(encoding="utf-8") != text:
            print(f"{OUT.relative_to(ROOT)} is out of date: run python3 scripts/build_workflow.py", file=sys.stderr)
            return 1
        print(f"{OUT.relative_to(ROOT)} is up to date")
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
