"""Guarantees that only hold inside one process are not guarantees.

These launch real interpreters against one shared database, because an in-process lock
proves nothing about a service running more than one replica. Children are subprocesses
rather than a pool so that a child dying reports its own stderr instead of a bare
BrokenProcessPool.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

from airlock import Airlock

WORKER = Path(__file__).parent / "mp_worker.py"
ROOT = Path(__file__).resolve().parents[1]


def _run(store_url: str, marker: Path, jobs: list[tuple[str, float]], cap: float) -> list[str]:
    marker.touch()
    running = [
        subprocess.Popen(
            [sys.executable, str(WORKER), store_url, str(marker), intent, str(amount), str(cap)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for intent, amount in jobs
    ]
    results = []
    for process in running:
        out, err = process.communicate(timeout=120)
        assert process.returncode == 0, f"worker died ({process.returncode}): {err}"
        results.append(out.strip())
    return results


def test_one_intent_executes_once_across_processes(tmp_path: Any) -> None:
    url = f"sqlite:///{tmp_path / 'airlock.db'}"
    marker = tmp_path / "runs"

    _run(url, marker, [("inv-77", 10.0)] * 4, cap=1_000)

    assert marker.read_text() == "x"


def test_a_shared_budget_is_not_overspent_across_processes(tmp_path: Any) -> None:
    url = f"sqlite:///{tmp_path / 'airlock.db'}"
    marker = tmp_path / "runs"

    _run(url, marker, [(f"inv-{n}", 100.0) for n in range(12)], cap=500)

    assert len(marker.read_text()) == 5


def test_the_audit_log_is_one_shared_record(tmp_path: Any) -> None:
    url = f"sqlite:///{tmp_path / 'airlock.db'}"
    marker = tmp_path / "runs"

    _run(url, marker, [(f"inv-{n}", 10.0) for n in range(4)], cap=1_000)

    lock = Airlock(store=url)
    assert len(lock.audit.query(outcome="executed")) == 4
    lock.close()
