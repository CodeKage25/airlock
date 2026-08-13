"""A guarded payment service, in the shape a real one has.

Postgres store, Prometheus metrics on /metrics, two replicas behind the same database.
Nothing here is special to the demo: this is the wiring a service actually needs.
"""

from __future__ import annotations

import json
import os
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from airlock import Airlock, Caps, Policy, approval
from airlock.adapters.mcp import refusal
from airlock.errors import AirlockError
from airlock.telemetry.prometheus import PrometheusTelemetry

metrics = PrometheusTelemetry()

lock = Airlock(
    policy=Policy(
        caps={
            "send_payment": Caps(
                max_per_call=1_000,
                max_per_day=10_000,
                currency="USD",
                scope_by="principal",
                max_calls_per_window=60,
                call_window=timedelta(minutes=1),
            )
        },
        approvals=[
            approval.when(
                "send_payment",
                lambda call: call.args["amount"] > 500,
                "payments over 500 need a human",
                ttl=timedelta(hours=4),
            )
        ],
    ),
    store=os.environ.get("AIRLOCK_STORE", "sqlite:///airlock.db"),
    telemetry=metrics,
    audit_redact=["beneficiary"],
    approval_ttl=timedelta(days=1),
)
metrics.watch(lock)


@lock.tool
def send_payment(to: str, amount: float, beneficiary: str = "", currency: str = "USD") -> str:
    """Send a payment. Stands in for a real rail."""
    return f"txn_{to}_{amount:.2f}"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.startswith("/metrics"):
            body = generate_latest()
            self._send(200, body, CONTENT_TYPE_LATEST)
        elif self.path.startswith("/health"):
            snapshot = lock.snapshot()
            self._json(200, {"ok": True, "stuck_intents": snapshot.stuck_intents})
        else:
            self._json(404, {"error": "try /pay, /metrics or /health"})

    def do_POST(self) -> None:
        if not self.path.startswith("/pay"):
            self._json(404, {"error": "try /pay"})
            return
        length = int(self.headers.get("content-length", 0))
        payload = json.loads(self.rfile.read(length) or b"{}")
        try:
            result = send_payment(
                to=payload["to"],
                amount=payload["amount"],
                beneficiary=payload.get("beneficiary", ""),
                _intent=payload["intent"],
                _principal=payload.get("principal", "agent://demo"),
            )
        except AirlockError as exc:
            # The refusal shape the adapters use, so a client sees one vocabulary.
            self._json(200, refusal(exc))
        except Exception as exc:
            self._json(502, {"airlock": "rail_error", "reason": str(exc)})
        else:
            self._json(200, {"airlock": "executed", "result": result})

    def log_message(self, *_: Any) -> None:
        return None

    def _json(self, status: int, body: dict[str, Any]) -> None:
        self._send(status, json.dumps(body).encode(), "application/json")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print(f"airlock service on :8000, store {lock.store.url}", flush=True)
    HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
