"""One attempt, in its own interpreter. Driven by tests/test_multiprocess.py."""

from __future__ import annotations

import sys

from airlock import Airlock, Caps, Policy


def main() -> int:
    store_url, marker, intent, amount, cap = sys.argv[1:6]
    lock = Airlock(
        policy=Policy(caps={"pay": Caps(max_per_day=cap)}),
        store=store_url,
    )

    @lock.tool
    def pay(amount: float) -> str:
        with open(marker, "a") as handle:
            handle.write("x")
        return "txn"

    try:
        print(pay(amount=float(amount), _intent=intent))
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}")
    finally:
        lock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
