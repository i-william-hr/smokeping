"""RRDtool storage and graph generation for smokeping results.

One RRD per (target, node), storing min/avg/max/mdev ms and loss percent.
Graphs are rendered on demand for 24h / 7d / 30d / 1y windows.
"""

from __future__ import annotations

import os
import time
from typing import Optional

import rrdtool

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")
GRAPH_DIR = os.path.join(HERE, "graphs")

# RRD: step 60s, one row per probe. Keep 1 year of 60s PDPs, plus consolidated
# RAAs for longer views. DSes: min, avg, max, mdev, loss (all GAUGE, ms / %).
_RRD_STEP = 60
# Must exceed the WORST-CASE pass cycle of the scheduler (serial probing of
# every target x node plus graph regeneration currently lands at ~6-9 min,
# occasionally more right after a restart). rrdtool discards an update whose
# gap since the previous one exceeds the heartbeat, so a 300s heartbeat with
# a >300s cycle silently threw away every probe: rows only ever committed in
# bursts right after restarts and the graphs thinned out to near-nothing.
_RRD_HEARTBEAT = 1800
_RRA = [
    "RRA:AVERAGE:0.5:1:1440",      # 60s x 1440 = 24h
    "RRA:AVERAGE:0.5:5:2016",      # 5min x 2016 = 7d
    "RRA:AVERAGE:0.5:60:730",      # 1h x 730 = ~30d
    "RRA:AVERAGE:0.5:720:730",     # 12h x 730 = ~365d
    "RRA:MIN:0.5:1:1440",
    "RRA:MAX:0.5:1:1440",
    "RRA:LAST:0.5:1:1",
]


def _rrd_path(target: str, node: str) -> str:
    return os.path.join(DATA_DIR, f"{target}__{node}.rrd")


def _graph_path(target: str, node: str, window: str) -> str:
    return os.path.join(GRAPH_DIR, f"{target}__{node}__{window}.png")


def ensure_dirs() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(GRAPH_DIR, exist_ok=True)


def _safe_name(s: str) -> str:
    """Filesystem-safe component for target/node names."""
    return "".join(c if c.isalnum() or c in "-_. " else "_" for c in s).strip()


def rrd_path(target: str, node: str) -> str:
    return _rrd_path(_safe_name(target), _safe_name(node))


def graph_path(target: str, node: str, window: str) -> str:
    return _graph_path(_safe_name(target), _safe_name(node), window)


def create_rrd(target: str, node: str) -> str:
    """Create the RRD for (target, node) if it doesn't exist. Returns path."""
    ensure_dirs()
    path = rrd_path(target, node)
    if os.path.exists(path):
        return path
    ds = [
        "DS:min:GAUGE:%d:U:U" % _RRD_HEARTBEAT,
        "DS:avg:GAUGE:%d:U:U" % _RRD_HEARTBEAT,
        "DS:max:GAUGE:%d:U:U" % _RRD_HEARTBEAT,
        "DS:mdev:GAUGE:%d:U:U" % _RRD_HEARTBEAT,
        "DS:loss:GAUGE:%d:U:U" % _RRD_HEARTBEAT,
    ]
    rrdtool.create(path, "--step", str(_RRD_STEP), *ds, *_RRA)
    return path


def update_rrd(target: str, node: str, result: dict) -> None:
    """Insert one probe result into the RRD for (target, node)."""
    path = create_rrd(target, node)
    # rrdtool update expects N:min:avg:max:mdev:loss — DS order is min,avg,max,mdev,loss
    values = (
        result.get("min") if result.get("min") is not None else "U",
        result.get("avg") if result.get("avg") is not None else "U",
        result.get("max") if result.get("max") is not None else "U",
        result.get("mdev") if result.get("mdev") is not None else "U",
        result.get("loss") if result.get("loss") is not None else "U",
    )
    rrdtool.update(path, f"N:{':'.join(str(v) for v in values)}")


def graph_rrd(target: str, node: str, window: str = "24h") -> Optional[str]:
    """Render (or reuse) a PNG graph for (target, node, window). Returns path.

    Serves the cached PNG when it is at least as new as the RRD; re-renders
    otherwise. Whatever regenerates graphs must go through here so a graph is
    never stale relative to its data.
    """
    ensure_dirs()
    path = graph_path(target, node, window)
    rrd = rrd_path(target, node)
    if not os.path.exists(rrd):
        return None

    # Regenerate if the graph is older than the RRD (fresh data arrived).
    regenerate = True
    if os.path.exists(path):
        regenerate = os.path.getmtime(path) < os.path.getmtime(rrd)
    if not regenerate:
        return path

    now = int(time.time())
    if window == "24h":
        start = f"e-{24*3600}"
        width = 700
    elif window == "7d":
        start = f"e-{7*24*3600}"
        width = 900
    elif window == "30d":
        start = f"e-{30*24*3600}"
        width = 1100
    elif window == "1y":
        start = f"e-{365*24*3600}"
        width = 1400
    else:
        start = f"e-{24*3600}"
        width = 700

    title = f"{target} — {node} ({window})"
    # Render to a temp file and rename: nginx serves these PNGs straight off
    # disk while the scheduler regenerates them, and rrdtool writes the image
    # incrementally, so rendering into the final name could hand out a torn
    # PNG. The temp name keeps a .png suffix because rrdtool picks the image
    # format from the file extension.
    tmp = f"{path}.tmp.png"
    try:
        rrdtool.graph(
            tmp,
            "--start", start,
            "--end", "now",
            "--width", str(width),
            "--height", "160",
            "--title", title,
            "--vertical-label", "ms",
            "--lower-limit", "0",
            f"DEF:avg={rrd}:avg:AVERAGE",
            f"DEF:min={rrd}:min:MIN",
            f"DEF:max={rrd}:max:MAX",
            f"DEF:loss={rrd}:loss:AVERAGE",
            "LINE1:avg#00aaff:avg",
            "LINE2:min#22cc22:min",
            "LINE2:max#ff4444:max",
            "COMMENT:\\n",
            "GPRINT:avg:AVERAGE:avg\\: %5.2lf ms",
            "GPRINT:min:MIN:min\\: %5.2lf ms",
            "GPRINT:max:MAX:max\\: %5.2lf ms",
            "GPRINT:loss:AVERAGE:loss\\: %5.2lf%%",
        )
        os.replace(tmp, path)
    except rrdtool.OperationalError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return None
    return path


def latest(target: str, node: str) -> Optional[dict]:
    """Return the most recent consolidated values for (target, node), or None."""
    path = rrd_path(target, node)
    if not os.path.exists(path):
        return None
    try:
        (t_start, _t_end, step), ds_names, rows = rrdtool.fetch(
            path, "AVERAGE", "-s", "e-1h", "-e", "now")
    except rrdtool.OperationalError:
        return None
    if not rows:
        return None
    # rows: list of value-tuples [min,avg,max,mdev,loss]; row i sits at
    # timestamp t_start + i*step. The most recent consolidated row can be None
    # while RRD is still catching up, so scan backward for the last non-None
    # row and report its timestamp.
    names = ["min", "avg", "max", "mdev", "loss"]
    ts = t_start + (len(rows) - 1) * step
    for idx in range(len(rows) - 1, -1, -1):
        vals = rows[idx]
        if any(v is not None for v in vals):
            ts = t_start + idx * step
            break
        vals = None
    if vals is None:
        return {"ts": ts}
    out = {"ts": ts}
    for name, val in zip(names, vals):
        out[name] = None if val is None else float(val)
    return out


def list_rrds() -> list[dict]:
    """List all RRDs with their target/node and latest values."""
    ensure_dirs()
    out = []
    if not os.path.isdir(DATA_DIR):
        return out
    for fname in sorted(os.listdir(DATA_DIR)):
        if not fname.endswith(".rrd"):
            continue
        base = fname[:-4]
        if "__" not in base:
            continue
        target, node = base.split("__", 1)
        lat = latest(target, node)
        out.append({"target": target, "node": node, "latest": lat})
    return out
