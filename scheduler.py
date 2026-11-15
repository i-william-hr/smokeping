"""Background probe scheduler for smokeping.

Runs a loop: every ``SMOKPING_INTERVAL`` seconds (default 60s), probes every
(target × enabled node) pair — except IPv6 targets from nodes whose
``probe_v6`` is disabled in nodes.json (see probe.skip_pair) — rate-limited
via probe.py's semaphore + per-node pacing, and writes results to RRDs. When
a new node is added (flagged via ``mark_node_added``), it immediately
enqueues a backlog probe of all targets from that node (still rate-limited)
so coverage starts right away.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from typing import Optional

import probe
import rrd

HERE = os.path.dirname(os.path.abspath(__file__))
TARGETS_PATH = os.path.join(HERE, "targets.json")
NODES_PATH = os.path.join(HERE, "nodes.json")

_INTERVAL = float(os.environ.get("SMOKPING_INTERVAL", "60"))


class Scheduler:
    def __init__(self) -> None:
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._nodes_changed = threading.Event()
        self._new_node_added = threading.Event()
        self._lock = threading.Lock()
        self._last_summary: dict = {}

    # --- config loading ---------------------------------------------------

    def _load_json(self, path: str, default):
        try:
            with open(path) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return default

    def _targets(self) -> list[dict]:
        return self._load_json(TARGETS_PATH, [])

    def _nodes(self) -> list[dict]:
        return self._load_json(NODES_PATH, [])

    # --- node add signal --------------------------------------------------

    def mark_node_added(self) -> None:
        """Called by the admin API when a node is added: triggers immediate
        backlog of all targets from the new node on the next scheduler tick."""
        self._new_node_added.set()
        self._nodes_changed.set()

    # --- run loop ---------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="smokeping-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._nodes_changed.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        # Prime with an immediate first pass so data appears without waiting
        # a full interval, then sleep interval between passes.
        self._pass()
        while not self._stop.wait(_INTERVAL):
            try:
                self._pass()
            except Exception:  # scheduler must never die
                import traceback
                traceback.print_exc()

    def _pass(self) -> None:
        targets = self._targets()
        nodes = [n for n in self._nodes() if n.get("enabled", True)]
        if not targets or not nodes:
            return

        backlog_node = None
        if self._new_node_added.is_set():
            self._new_node_added.clear()
            # backlog: probe every target from the most recently added node
            backlog_node = nodes[-1] if nodes else None

        results = []
        for target in targets:
            for node in nodes:
                if probe.skip_pair(target, node):
                    continue
                res = probe.probe_target(target, node)
                results.append(res)
                rrd.update_rrd(target["name"], node["name"], res)
        # backlog from newly added node (in addition to regular pass)
        if backlog_node is not None:
            for target in targets:
                if probe.skip_pair(target, backlog_node):
                    continue
                res = probe.probe_target(target, backlog_node)
                results.append(res)
                rrd.update_rrd(target["name"], backlog_node["name"], res)

        self._last_summary = {
            "ts": time.time(),
            "probes": len(results),
            "ok": sum(1 for r in results if r["ok"]),
            "failed": sum(1 for r in results if not r["ok"]),
        }

        # Probe failures are silent by design (an unreachable target is a
        # gap in the RRD, not an error), but the reason is worth one journal
        # line per pass so a systematically failing pair is debuggable.
        failed = [r for r in results if not r["ok"]]
        if failed:
            print("[probe] %d/%d probes failed:" % (len(failed), len(results)),
                  file=sys.stderr)
            for r in failed[:25]:
                print("  %s <- %s: %s" % (r["target"], r["node"], r["error"]),
                      file=sys.stderr)

        self._refresh_graphs(targets, nodes)

    def _refresh_graphs(self, targets, nodes) -> None:
        """Re-render every graph PNG whose RRD is newer than the PNG.

        nginx serves /graphs/ straight off disk, so a PNG left behind by an
        older pass is what users see — that is how the site once showed
        all-NaN graphs for a day. graph_rrd() itself skips fresh PNGs, so
        this only pays for graphs whose data actually moved. The 24h window
        is the only one the UI links to; the longer windows are refreshed
        only once their PNG exists (someone has viewed them), so never-viewed
        windows cost nothing.
        """
        for target in targets:
            for node in nodes:
                if probe.skip_pair(target, node):
                    continue
                try:
                    rrd.graph_rrd(target["name"], node["name"], "24h")
                    for window in ("7d", "30d", "1y"):
                        if os.path.exists(rrd.graph_path(target["name"], node["name"], window)):
                            rrd.graph_rrd(target["name"], node["name"], window)
                except Exception:
                    import traceback
                    traceback.print_exc()

    def summary(self) -> dict:
        return dict(self._last_summary)


# module-level singleton
scheduler = Scheduler()
