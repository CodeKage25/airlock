"""A fake multi-leg payment rail. Legs are independent and only the last one is reversible."""

from __future__ import annotations

from dataclasses import dataclass, field


class RailTimeout(Exception):
    """The rail accepted the request and then went quiet. The worst possible answer."""


@dataclass
class Rail:
    settled: list[tuple[str, float]] = field(default_factory=list)
    fail_on: set[str] = field(default_factory=set)
    quote: float = 1500.0
    live: float = 1500.0

    def leg(self, name: str, amount: float) -> str:
        if name in self.fail_on:
            self.settled.append((name, amount))
            raise RailTimeout(f"{name} did not respond")
        self.settled.append((name, amount))
        return f"{name}_{len(self.settled):03d}"

    def moved(self) -> float:
        return sum(amount for _, amount in self.settled)

    def slippage(self) -> float:
        return abs(self.live - self.quote) / self.quote
