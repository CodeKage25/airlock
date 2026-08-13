"""Operator CLI.

The commands here are the ones someone reaches for during an incident, so they work
against a store URL alone. Approving is the exception: executing a parked call needs the
registered tools, so it needs the application object too.
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys
from datetime import timedelta
from typing import Any

from airlock.errors import AirlockError
from airlock.lock import Airlock

ENV_STORE = "AIRLOCK_STORE"


def _store_url(args: argparse.Namespace) -> str:
    url = args.store or os.environ.get(ENV_STORE)
    if not url:
        raise SystemExit(f"pass --store or set {ENV_STORE}")
    return url


def _bare(args: argparse.Namespace) -> Airlock:
    return Airlock(store=_store_url(args))


def _app(args: argparse.Namespace) -> Airlock:
    """Import the application's configured Airlock, e.g. --app myservice.agent:lock."""
    if not args.app:
        raise SystemExit("--app module:attribute is required to approve a request")
    module_name, _, attribute = args.app.partition(":")
    if not attribute:
        raise SystemExit("--app must look like module:attribute")
    lock = getattr(importlib.import_module(module_name), attribute)
    if not isinstance(lock, Airlock):
        raise SystemExit(f"{args.app} is a {type(lock).__name__}, not an Airlock")
    return lock


def _table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows)) if rows else len(headers[i])
        for i in range(len(headers))
    ]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True))
    out = [line, "  ".join("-" * w for w in widths)]
    out += ["  ".join(cell.ljust(w) for cell, w in zip(row, widths, strict=True)) for row in rows]
    return "\n".join(out)


def intents_stuck(args: argparse.Namespace) -> int:
    lock = _bare(args)
    older = timedelta(minutes=args.older_than) if args.older_than else None
    stuck = lock.intents.stuck(older_than=older, limit=args.limit)
    if not stuck:
        print("no stuck intents")
        return 0
    print(
        _table(
            [
                [
                    item.key[:16],
                    item.tool,
                    item.intent,
                    item.state.value,
                    str(item.age).split(".")[0],
                ]
                for item in stuck
            ],
            ["KEY", "TOOL", "INTENT", "STATE", "AGE"],
        )
    )
    print(
        f"\n{len(stuck)} stuck. Resolve each with:\n"
        "  airlock intents resolve <KEY> --executed|--not-executed --by you@company.com"
    )
    return 0


def intents_resolve(args: argparse.Namespace) -> int:
    if args.executed == args.not_executed:
        raise SystemExit("pass exactly one of --executed or --not-executed")
    lock = _bare(args)
    lock.intents.resolve(args.key, executed=args.executed, by=args.by, note=args.note or "")
    verdict = "executed" if args.executed else "did not execute"
    print(f"resolved {args.key[:16]} as {verdict}, recorded against {args.by}")
    return 0


def approvals_pending(args: argparse.Namespace) -> int:
    lock = _bare(args)
    requests = lock.approvals.pending()
    if not requests:
        print("no pending approvals")
        return 0
    print(
        _table(
            [
                [r.id, r.tool, r.intent, r.reason[:48], str(r.expires_at or "never")]
                for r in requests
            ],
            ["ID", "TOOL", "INTENT", "REASON", "EXPIRES"],
        )
    )
    return 0


def approvals_approve(args: argparse.Namespace) -> int:
    lock = _app(args)
    result = lock.approvals.approve(args.id, by=args.by)
    print(f"approved {args.id} as {args.by}: {result!r}")
    return 0


def approvals_reject(args: argparse.Namespace) -> int:
    lock = _bare(args)
    lock.approvals.reject(args.id, reason=args.reason)
    print(f"rejected {args.id}: {args.reason}")
    return 0


def audit(args: argparse.Namespace) -> int:
    lock = _bare(args)
    entries = lock.audit.query(
        tool=args.tool, intent=args.intent, outcome=args.outcome, limit=args.limit
    )
    if not entries:
        print("no matching audit entries")
        return 0
    print(
        _table(
            [
                [
                    e.at.isoformat(timespec="seconds"),
                    e.tool,
                    e.intent,
                    e.outcome.value,
                    e.layer or "",
                    (e.reason or "")[:56],
                ]
                for e in entries
            ],
            ["AT", "TOOL", "INTENT", "OUTCOME", "LAYER", "REASON"],
        )
    )
    return 0


def shadow_report(args: argparse.Namespace) -> int:
    lock = _bare(args)
    report = lock.shadow.report(tool=args.tool)
    print(report.render())
    # Non-zero when enforcing would change something, so this can gate a promotion.
    return 1 if (args.strict and not report.clean) else 0


def migrate(args: argparse.Namespace) -> int:
    from airlock.core.stores import migrations

    lock = _bare(args)
    version = getattr(lock.store, "schema_version", lambda: migrations.CURRENT)()
    print(f"{lock.store.url}\nschema version {version} (latest {migrations.CURRENT})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="airlock", description=__doc__)
    parser.add_argument("--store", help=f"store url, or set {ENV_STORE}")
    parser.add_argument("--app", help="module:attribute holding the configured Airlock")
    commands = parser.add_subparsers(dest="command", required=True)

    intents = commands.add_parser("intents", help="inspect and resolve stuck intents")
    intents_sub = intents.add_subparsers(dest="subcommand", required=True)

    stuck = intents_sub.add_parser("stuck", help="list intents that stopped making progress")
    stuck.add_argument("--older-than", type=int, metavar="MINUTES")
    stuck.add_argument("--limit", type=int, default=100)
    stuck.set_defaults(handler=intents_stuck)

    resolve = intents_sub.add_parser("resolve", help="settle a stuck intent")
    resolve.add_argument("key")
    resolve.add_argument("--executed", action="store_true", help="the action did land")
    resolve.add_argument("--not-executed", action="store_true", help="the action did not land")
    resolve.add_argument("--by", required=True, metavar="WHO")
    resolve.add_argument("--note")
    resolve.set_defaults(handler=intents_resolve)

    approvals = commands.add_parser("approvals", help="work the approval queue")
    approvals_sub = approvals.add_subparsers(dest="subcommand", required=True)

    listing = approvals_sub.add_parser("pending", help="list requests waiting on a human")
    listing.set_defaults(handler=approvals_pending)

    approve = approvals_sub.add_parser("approve", help="approve and execute a request")
    approve.add_argument("id")
    approve.add_argument("--by", required=True, metavar="WHO")
    approve.set_defaults(handler=approvals_approve)

    reject = approvals_sub.add_parser("reject", help="close a request without executing")
    reject.add_argument("id")
    reject.add_argument("--reason", required=True)
    reject.set_defaults(handler=approvals_reject)

    shadow = commands.add_parser("shadow", help="what observe-only mode would have stopped")
    shadow_sub = shadow.add_subparsers(dest="subcommand", required=True)
    shadow_rep = shadow_sub.add_parser("report", help="what enforcing would have changed")
    shadow_rep.add_argument("--tool")
    shadow_rep.add_argument(
        "--strict", action="store_true", help="exit non-zero if anything would be stopped"
    )
    shadow_rep.set_defaults(handler=shadow_report)

    log = commands.add_parser("audit", help="query the audit log")
    log.add_argument("--tool")
    log.add_argument("--intent")
    log.add_argument("--outcome")
    log.add_argument("--limit", type=int, default=50)
    log.set_defaults(handler=audit)

    status = commands.add_parser("migrate", help="report the applied schema version")
    status.set_defaults(handler=migrate)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler: Any = args.handler
    try:
        return int(handler(args))
    except AirlockError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
