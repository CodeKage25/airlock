#!/usr/bin/env python3
"""A payment agent that cannot hurt you.

Runs the failures first, because the happy path is not the interesting part.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from airlock import Airlock, Call, Caps, Decision, Policy, approval
from airlock.errors import Blocked, PendingApproval
from examples.payment_agent.rail import Rail, RailTimeout

BOLD, DIM, GREEN, RED, YELLOW, OFF = (
    "\033[1m",
    "\033[2m",
    "\033[32m",
    "\033[31m",
    "\033[33m",
    "\033[0m",
)

rail = Rail()


def fx_slippage(call: Call) -> Decision:
    if rail.slippage() > 0.02:
        return Decision.escalate(
            f"fx moved {rail.slippage():.1%} from the quote, beyond the 2% tolerance"
        )
    return Decision.allow()


def unsettled_legs(call: Call) -> Decision:
    if call.context.get("previous_leg_unconfirmed"):
        return Decision.escalate("an earlier leg settled but was never confirmed")
    return Decision.allow()


lock = Airlock(
    policy=Policy(
        caps={
            "settle_leg": Caps(max_per_call=1_000, max_per_day=2_000, currency="USD"),
        },
        approvals=[
            approval.when(
                "settle_leg",
                lambda call: call.args["leg"] == "off_ramp" and call.args["amount"] > 500,
                "off-ramp over 500 is one-way",
            ),
        ],
        risk_hooks=[fx_slippage, unsettled_legs],
    ),
    store="memory://",
    audit_redact=["beneficiary"],
)


@lock.tool
def settle_leg(leg: str, amount: float, beneficiary: str, currency: str = "USD") -> str:
    """Settle one leg of a payment."""
    return rail.leg(leg, amount)


def attempt(label: str, note: str, thunk) -> None:  # type: ignore[no-untyped-def]
    before = len(rail.settled)
    try:
        result = thunk()
        ran = len(rail.settled) > before
        tag = f"{GREEN}executed{OFF} " if ran else f"{GREEN}replayed{OFF} "
        print(f"  {tag} {label}\n            {DIM}{note} -> {result}{OFF}")
    except Blocked as exc:
        print(f"  {RED}blocked {OFF}  {label}\n            {DIM}[{exc.layer}] {exc.reason}{OFF}")
    except PendingApproval as exc:
        print(
            f"  {YELLOW}escalated{OFF} {label}\n            {DIM}{exc.reason} "
            f"(request {exc.request_id}){OFF}"
        )
    except RailTimeout as exc:
        print(f"  {RED}rail down{OFF} {label}\n            {DIM}{exc}{OFF}")


print(f"\n{BOLD}Airlock stopping a payment agent from doing damage{OFF}\n")

print(f"{BOLD}1. The agent retries a payment it already made{OFF}")
attempt(
    "on-ramp 400 USD",
    "first attempt",
    lambda: settle_leg(leg="on_ramp", amount=400, beneficiary="acct_123", _intent="inv-77"),
)
attempt(
    "on-ramp 400 USD",
    "same intent, retried after a client timeout",
    lambda: settle_leg(leg="on_ramp", amount=400, beneficiary="acct_123", _intent="inv-77"),
)
print(f"  {DIM}rail moved {rail.moved():.0f} USD, not 800{OFF}\n")

print(f"{BOLD}2. The agent tries a payment above its per-call cap{OFF}")
attempt(
    "transfer 5,000 USD",
    "the model read the wrong invoice",
    lambda: settle_leg(leg="transfer", amount=5_000, beneficiary="acct_123", _intent="inv-78"),
)
print()

print(f"{BOLD}3. The agent rewrites the beneficiary on a retry{OFF}")
attempt(
    "on-ramp 400 USD to acct_evil",
    "same intent, different destination",
    lambda: settle_leg(leg="on_ramp", amount=400, beneficiary="acct_evil", _intent="inv-77"),
)
print()

print(f"{BOLD}4. The market moves between quote and settlement{OFF}")
rail.live = 1_620.0
attempt(
    "transfer 400 USD",
    "fx slipped 8% while the agent was reasoning",
    lambda: settle_leg(leg="transfer", amount=400, beneficiary="acct_123", _intent="inv-79"),
)
rail.live = 1_500.0
print()

print(f"{BOLD}5. The irreversible leg times out, then the agent retries{OFF}")
rail.fail_on = {"off_ramp"}
attempt(
    "off-ramp 300 USD",
    "no response from the rail",
    lambda: settle_leg(leg="off_ramp", amount=300, beneficiary="acct_123", _intent="inv-80"),
)
attempt(
    "off-ramp 300 USD",
    "the agent assumes it failed and tries again",
    lambda: settle_leg(leg="off_ramp", amount=300, beneficiary="acct_123", _intent="inv-80"),
)
rail.fail_on = set()
print()

print(f"{BOLD}6. A partial settlement reaches a human{OFF}")
attempt(
    "off-ramp 300 USD",
    "an earlier leg is unconfirmed",
    lambda: settle_leg(
        leg="off_ramp",
        amount=300,
        beneficiary="acct_123",
        _intent="inv-81",
        _context={"previous_leg_unconfirmed": True},
    ),
)
print()

print(f"{BOLD}7. A one-way action waits for sign-off, then runs once{OFF}")
attempt(
    "off-ramp 600 USD",
    "over the one-way threshold",
    lambda: settle_leg(leg="off_ramp", amount=600, beneficiary="acct_123", _intent="inv-82"),
)
request = next(r for r in lock.approvals.pending() if r.intent == "inv-82")
attempt("off-ramp 600 USD", "approved by ops", lambda: request.approve(by="ops@yourco.com"))
attempt(
    "off-ramp 600 USD",
    "the agent retries after the approval",
    lambda: settle_leg(leg="off_ramp", amount=600, beneficiary="acct_123", _intent="inv-82"),
)
print()

print(f"{BOLD}8. The runaway loop hits the daily cap{OFF}")
for n in range(4):
    attempt(
        f"transfer 400 USD (#{n + 1})",
        "the agent is stuck in a retry loop",
        lambda n=n: settle_leg(
            leg="transfer", amount=400, beneficiary="acct_123", _intent=f"loop-{n}"
        ),
    )
print()

print(f"{BOLD}What the audit log says{OFF}")
counts: dict[str, int] = {}
for entry in lock.audit.query():
    counts[entry.outcome.value] = counts.get(entry.outcome.value, 0) + 1
print(f"  {DIM}{counts}{OFF}")
print(
    f"  {DIM}beneficiary is redacted: "
    f"{lock.audit.query(outcome='executed')[0].args['beneficiary']}{OFF}"
)
print(f"\n  {BOLD}the rail moved {rail.moved():.0f} USD in total{OFF}")
print(f"  {DIM}every leg above was proposed by the agent; the pipeline decided which ran{OFF}\n")
