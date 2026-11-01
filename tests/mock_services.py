#!/usr/bin/env python3
"""Fake LLM / AbuseIPDB / Telegram server for testing the workflow without real keys.

It answers the three HTTP calls the n8n workflow makes:
  POST /v1/chat/completions      (OpenAI-compatible LLM, like LM Studio)
  GET  /api/v2/check             (AbuseIPDB)
  POST /bot<token>/sendMessage   (Telegram)
and records every request, which you can read back with GET /_requests.
Secrets in the record (API key headers, the bot token in the path) are replaced by
"<redacted>". Only use placeholder keys with it anyway: it is a test tool.

POST /_config {"llm": "ok"|"fail"|"invalid", "telegram": "ok"|"fail"} switches failure
modes at runtime (used by tests/e2e/run_e2e.py). POST /_reset clears the record.

Point the workflow at it with these environment variables:
  LLM_BASE_URL=http://<host>:8999/v1
  ABUSEIPDB_API_URL=http://<host>:8999/api/v2/check
  TELEGRAM_API_BASE=http://<host>:8999

Run:  python3 tests/mock_services.py [--host 127.0.0.1] [--port 8999] [--llm-fail]
It listens on 127.0.0.1 by default. Use --host 0.0.0.0 only on an isolated test network
(for example so n8n in Docker can reach it).
"""
import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

REQUESTS = []
MODES = {"llm": "ok", "telegram": "ok"}
SECRET_HEADERS = {"authorization", "key", "x-wazuh-token"}


def fake_triage(prompt):
    """Very small rule-based stand-in for a real model."""
    text = prompt.lower()
    if "brute force" in text or "invalid user" in text:
        return {
            "verdict": "true_positive",
            "severity": "high",
            "confidence": 90,
            "summary": "Repeated SSH logins for a non-existent user from one public IP: a brute force attempt.",
            "reasoning": "Wazuh correlated many failed logins; the IP has a bad reputation.",
            "mitre_technique_id": "T1110",
            "mitre_technique_name": "Brute Force",
            "recommended_actions": ["Block the source IP", "Disable SSH password login"],
            "block_source_ip": True,
        }
    if "sql injection" in text:
        return {
            "verdict": "true_positive",
            "severity": "high",
            "confidence": 85,
            "summary": "sqlmap UNION SELECT request against products.php.",
            "reasoning": "Classic SQL injection payload and an attack tool user agent.",
            "mitre_technique_id": "T1190",
            "mitre_technique_name": "Exploit Public-Facing Application",
            "recommended_actions": ["Check the web app for SQL injection", "Block the source IP"],
            "block_source_ip": True,
        }
    return {
        "verdict": "needs_investigation",
        "severity": "medium",
        "confidence": 60,
        "summary": "Activity needs a human look.",
        "reasoning": "Not enough context to decide.",
        "mitre_technique_id": "",
        "mitre_technique_name": "",
        "recommended_actions": ["Confirm whether this change was expected"],
        "block_source_ip": False,
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record(self, body):
        headers = {k: ("<redacted>" if k.lower() in SECRET_HEADERS else v) for k, v in self.headers.items()}
        path = re.sub(r"^/bot[^/]+/", "/bot<redacted>/", self.path)
        REQUESTS.append({"method": self.command, "path": path, "headers": headers, "body": body})

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/_requests":
            return self._send(200, REQUESTS)
        self._record(None)
        if url.path == "/api/v2/check":
            if not self.headers.get("Key"):
                return self._send(401, {"errors": [{"detail": "Authentication failed"}]})
            ip = parse_qs(url.query).get("ipAddress", [""])[0]
            return self._send(
                200,
                {
                    "data": {
                        "ipAddress": ip,
                        "isPublic": True,
                        "abuseConfidenceScore": 100,
                        "countryCode": "NL",
                        "usageType": "Data Center/Web Hosting/Transit",
                        "isp": "Example Hosting",
                        "totalReports": 1342,
                        "isTor": False,
                        "lastReportedAt": "2026-10-29T15:01:00+00:00",
                    }
                },
            )
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode() if length else ""
        try:
            body = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            body = raw
        path = urlparse(self.path).path
        if path == "/_config":
            MODES.update({k: v for k, v in (body or {}).items() if k in MODES})
            return self._send(200, MODES)
        if path == "/_reset":
            REQUESTS.clear()
            MODES.update({"llm": "ok", "telegram": "ok"})
            return self._send(200, {"ok": True})
        self._record(body)
        if path == "/v1/chat/completions":
            if MODES["llm"] == "fail":
                return self._send(500, {"error": {"message": "model crashed (simulated)"}})
            prompt = json.dumps(body)
            # "invalid" answers with JSON that is well-formed but breaks the schema.
            content = json.dumps({} if MODES["llm"] == "invalid" else fake_triage(prompt))
            return self._send(
                200,
                {
                    "id": "chatcmpl-mock",
                    "object": "chat.completion",
                    "model": (body or {}).get("model", "mock"),
                    "choices": [
                        {"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}
                    ],
                },
            )
        if re.fullmatch(r"/bot[^/]+/sendMessage", path):
            if MODES["telegram"] == "fail":
                return self._send(502, {"ok": False, "description": "Bad Gateway (simulated)"})
            if not (body or {}).get("chat_id"):
                return self._send(400, {"ok": False, "description": "Bad Request: chat_id is empty"})
            return self._send(200, {"ok": True, "result": {"message_id": len(REQUESTS)}})
        return self._send(404, {"error": "not found"})


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1", help="address to listen on (default: loopback only)")
    parser.add_argument("--port", type=int, default=8999)
    parser.add_argument("--llm-fail", action="store_true", help="make the LLM endpoint return HTTP 500")
    args = parser.parse_args()
    if args.llm_fail:
        MODES["llm"] = "fail"
    print(f"mock services listening on {args.host}:{args.port}", flush=True)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
