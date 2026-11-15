"""Daily traceroutes from every probe node to every target.

One trace per (target, node) pair per day, stored as plain text under
``traces/<target>/<node>/<YYYY-MM-DD>.txt`` and browsable at ``/traces/`` on
the public site. Runs as a thread inside the web service process, same
pattern as the ping scheduler in scheduler.py — no separate unit.

Sanitization: the trace pages are public, so leading hops that sit on
private or VPN addresses (RFC1918, CGNAT, loopback, link-local, ULA and this
box's WireGuard prefix [REDACTED:internal-ipv6]/48) are stripped and the trace
renumbered; any internal-range address further into the trace is masked as
``<internal>``. Without this the remote nodes' WireGuard first hops (and the
box's internal topology) would be published to the internet.

Retention: with SMOKPING_TRACE_RETENTION_DAYS unset (the default, "unlimited")
every trace is kept loose on disk. When set, traces older than the retention
window are packed into monthly tar.gz archives under the traceping ZFS
dataset (mounted at [REDACTED:server-path], quota 2G) and the loose
copies are deleted. The archive directory is kept at or under
SMOKPING_TRACE_ARCHIVE_MAX_BYTES (default 1 GiB) by dropping the oldest
months first, so archived traces never grow past the cap.

Remote nodes run the same traceroute command over SSH (paramiko, same key
discovery as probe.py). Binary fallback: traceroute -> tracepath, detected
at runtime per node — a node with neither records an error for that day.

Configuration (environment, all optional):
    SMOKPING_TRACE_AT             daily run time HH:MM, default "04:20" (UTC)
    SMOKPING_TRACE_MAX_HOPS       default 20
    SMOKPING_TRACE_WAIT           per-probe wait seconds, default 3
    SMOKPING_TRACE_PROBES         probes per hop, default 1
    SMOKPING_TRACE_CONCURRENCY    in-flight traces, default 2
    SMOKPING_TRACE_NODE_PACE      min seconds between a node's trace starts, default 1.0
    SMOKPING_TRACE_RETENTION_DAYS unset/0 = keep everything loose
    SMOKPING_TRACE_ARCHIVE_DIR    default [REDACTED:server-path]
    SMOKPING_TRACE_ARCHIVE_MAX_BYTES  default 1073741824 (1 GiB)

The unit must name the archive dir in ReadWritePaths (ProtectSystem=strict
otherwise makes it read-only) — see smokeping.service.
"""

from __future__ import annotations

import io
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Optional

import rrd
import probe

HERE = os.path.dirname(os.path.abspath(__file__))
TRACES_DIR = os.path.join(HERE, "traces")

_TRACE_AT = os.environ.get("SMOKPING_TRACE_AT", "04:20")
_TRACE_MAX_HOPS = int(os.environ.get("SMOKPING_TRACE_MAX_HOPS", "20"))
_TRACE_WAIT = int(os.environ.get("SMOKPING_TRACE_WAIT", "3"))
_TRACE_PROBES = int(os.environ.get("SMOKPING_TRACE_PROBES", "1"))
_TRACE_CONCURRENCY = int(os.environ.get("SMOKPING_TRACE_CONCURRENCY", "2"))
_TRACE_NODE_PACE = float(os.environ.get("SMOKPING_TRACE_NODE_PACE", "1.0"))
_TRACE_RETENTION_DAYS = int(os.environ.get("SMOKPING_TRACE_RETENTION_DAYS", "0") or 0)
_ARCHIVE_DIR = os.environ.get("SMOKPING_TRACE_ARCHIVE_DIR",
                              "[REDACTED:server-path]")
_ARCHIVE_MAX_BYTES = int(os.environ.get("SMOKPING_TRACE_ARCHIVE_MAX_BYTES",
                                        str(1024 * 1024 * 1024)))

# Worst-case wall clock for one trace: every hop times out.
_TRACE_CMD_TIMEOUT = _TRACE_MAX_HOPS * _TRACE_WAIT * _TRACE_PROBES + 60

# Addresses that must never appear on the public site. 10/8 covers the
# WireGuard v4 net; 14c8::/48 is the WG v6 prefix (see AGENTS.md wg_gui note).
_INTERNAL_V4 = [
    "[REDACTED:internal-ipv4]/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
]
_INTERNAL_V6 = [
    "fc00::/7", "fe80::/10", "::1/128", "::/128",
    "[REDACTED:internal-ipv6]/48",
]
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")
# A hop line starts with an optional-padded number, optionally followed by
# "?" or "?:" (tracepath marks unresolved probes that way), then whitespace.
_HOP_RE = re.compile(r"^(\s*)(\d+)(\?\?)?:?")


def _internal_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    nets = _INTERNAL_V4 if addr.version == 4 else _INTERNAL_V6
    return any(addr in ipaddress.ip_network(n) for n in nets)


def _line_ips(line: str) -> list[str]:
    """Validated IP address strings appearing in a trace line."""
    out = []
    for cand in _IPV4_RE.findall(line):
        try:
            ipaddress.IPv4Address(cand)
            out.append(cand)
        except ValueError:
            continue
    for cand in _IPV6_RE.findall(line):
        try:
            ipaddress.IPv6Address(cand)
            out.append(cand)
        except ValueError:
            continue
    return out


def sanitize_trace(raw: str) -> str:
    """Make a raw traceroute/tracepath output safe for the public site.

    Leading hops with no public address (the WireGuard tunnel hops on the
    remote nodes) are dropped and the remaining hops renumbered from 1; any
    internal-range address anywhere else is replaced by <internal>. A trace
    with no public hop at all (target unreachable behind the tunnel) keeps
    all its lines, masked — the failure mode itself is worth showing.
    """
    lines = raw.rstrip("\n").splitlines()

    def hop_num(line: str) -> Optional[int]:
        m = _HOP_RE.match(line)
        return int(m.group(2)) if m else None

    first_public = None
    for i, line in enumerate(lines):
        if hop_num(line) is not None and any(
                not _internal_ip(ip) for ip in _line_ips(line)):
            first_public = i
            break
    if first_public is not None:
        lines = [line for j, line in enumerate(lines)
                 if not (j < first_public and hop_num(line) is not None)]

    # Renumber the remaining hop lines from 1. Repeated old number -> same
    # new number, so tracepath's multi-line hops stay grouped.
    new = 0
    prev_old = 0
    out = []
    for line in lines:
        old = hop_num(line)
        if old is not None:
            if old > prev_old:
                new += 1
                prev_old = old
            line = _HOP_RE.sub(
                lambda m: "%s%d%s" % (m.group(1), new, m.group(3) or ""),
                line, count=1)
        out.append(line)

    # Mask any internal address left anywhere in the trace.
    masked = []
    for line in out:
        for ip in _line_ips(line):
            if _internal_ip(ip):
                line = line.replace(ip, "<internal>")
        masked.append(line)
    return "\n".join(masked) + "\n"


# --- execution -------------------------------------------------------------

def _build_traceroute_cmd(host: str) -> str:
    return "traceroute -n -m %d -w %d -q %d %s" % (
        _TRACE_MAX_HOPS, _TRACE_WAIT, _TRACE_PROBES, host)


def trace_local(host: str) -> tuple[str, str]:
    """Run traceroute on this box. Returns (sanitized body, tool)."""
    binary = shutil.which("traceroute")
    if binary is not None:
        tool = "traceroute"
        cmd = [binary, "-n", "-m", str(_TRACE_MAX_HOPS), "-w", str(_TRACE_WAIT),
               "-q", str(_TRACE_PROBES), host]
    else:
        binary = shutil.which("tracepath")
        if binary is None:
            raise RuntimeError("no traceroute or tracepath binary found")
        tool = "tracepath"
        cmd = [binary, host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=_TRACE_CMD_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("traceroute timed out after %ds" % _TRACE_CMD_TIMEOUT) from exc
    text = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0 and not text.strip():
        raise RuntimeError("traceroute exited %d with no output" % proc.returncode)
    return sanitize_trace(text), tool


def trace_remote(node: dict, host: str) -> tuple[str, str]:
    """Run traceroute on a remote node over SSH. Returns (sanitized body, tool)."""
    import paramiko  # type: ignore

    from probe import _remote_ssh_key

    ssh_host = node["host"]
    ssh_user = node.get("ssh_user") or "root"
    ssh_port = int(node.get("ssh_port") or 22)
    key = _remote_ssh_key()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs = dict(hostname=ssh_host, port=ssh_port, username=ssh_user,
                              timeout=10, look_for_keys=True)
        if key:
            connect_kwargs["key_filename"] = key
        client.connect(**connect_kwargs)
        _, stdout, stderr = client.exec_command(
            _build_traceroute_cmd(host), timeout=_TRACE_CMD_TIMEOUT)
        text = stdout.read().decode(errors="replace") + stderr.read().decode(errors="replace")
        rc = stdout.channel.recv_exit_status()
        tool = "traceroute"
        if rc != 0 and not text.strip():
            # traceroute may be missing on the node: fall back to tracepath,
            # first with -m, then plain (old iputils has no -m).
            for tcmd, tname in (("tracepath -m %d %s" % (_TRACE_MAX_HOPS, host),
                                 "tracepath"),
                                ("tracepath %s" % host, "tracepath")):
                _, stdout, stderr = client.exec_command(tcmd, timeout=_TRACE_CMD_TIMEOUT)
                text = stdout.read().decode(errors="replace") + stderr.read().decode(errors="replace")
                rc = stdout.channel.recv_exit_status()
                if rc == 0 and text.strip():
                    tool = tname
                    break
            else:
                raise RuntimeError("traceroute on %s exited %d: %s" % (
                    ssh_host, rc, text.strip()[:200]))
    except Exception as exc:
        raise RuntimeError("trace from %s failed: %s" % (ssh_host, exc)) from exc
    finally:
        client.close()
    return sanitize_trace(text), tool


# --- pacing (separate from probe.py's ping pacing on purpose) --------------

_sem = threading.Semaphore(_TRACE_CONCURRENCY)
_node_locks: dict[str, threading.Lock] = {}
_node_locks_guard = threading.Lock()
_node_last: dict[str, float] = {}


def _node_lock(node: str) -> threading.Lock:
    with _node_locks_guard:
        lock = _node_locks.get(node)
        if lock is None:
            lock = threading.Lock()
            _node_locks[node] = lock
        return lock


def _pace(node_name: str) -> None:
    lock = _node_lock(node_name)
    with lock:
        last = _node_last.get(node_name, 0.0)
        wait = _TRACE_NODE_PACE - (time.time() - last)
        if wait > 0:
            time.sleep(wait)
        _node_last[node_name] = time.time()


# --- storage ---------------------------------------------------------------

def _pair_dir(target: str, node: str) -> str:
    return os.path.join(TRACES_DIR, rrd._safe_name(target), rrd._safe_name(node))


def list_dates(target: str, node: str) -> list[str]:
    """Sorted (oldest first) YYYY-MM-DD dates that have a stored trace."""
    d = _pair_dir(target, node)
    if not os.path.isdir(d):
        return []
    out = []
    for fname in os.listdir(d):
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.txt", fname):
            out.append(fname[:-4])
    return sorted(out)


def latest_trace(target: str, node: str) -> Optional[str]:
    dates = list_dates(target, node)
    return dates[-1] if dates else None


def trace_path(target: str, node: str, date: str) -> Optional[str]:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        return None
    path = os.path.join(_pair_dir(target, node), date + ".txt")
    return path if os.path.isfile(path) else None


def read_trace(target: str, node: str, date: str) -> Optional[str]:
    path = trace_path(target, node, date)
    if path is None:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _store(target: str, node: str, host: str, body: str, tool: str,
           when: datetime) -> str:
    d = _pair_dir(target, node)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, when.strftime("%Y-%m-%d") + ".txt")
    header = (
        "# target: %s\n# node: %s\n# host: %s\n"
        "# date: %s\n# tool: %s\n"
        "# sanitized: leading private/VPN hops stripped; internal addresses masked\n\n"
        % (target, node, host, when.strftime("%Y-%m-%d %H:%M UTC"), tool)
    )
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(header + body)
    os.replace(tmp, path)
    return path


# --- daily run -------------------------------------------------------------

def _targets_and_nodes() -> tuple[list[dict], list[dict]]:
    def _load(path):
        try:
            with open(path) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return []
    targets = _load(os.path.join(HERE, "targets.json"))
    nodes = [n for n in _load(os.path.join(HERE, "nodes.json"))
             if n.get("enabled", True)]
    return targets, nodes


def _pairs() -> list[tuple[dict, dict]]:
    targets, nodes = _targets_and_nodes()
    return [(t, n) for t in targets for n in nodes
            if not probe.skip_pair(t, n)]


def _today_complete() -> bool:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for t, n in _pairs():
        if latest_trace(t["name"], n["name"]) != today:
            return False
    return True


def _run_pair(target: dict, node: dict, when: datetime) -> dict:
    name, node_name, host = target["name"], node["name"], target["host"]
    t0 = time.time()
    try:
        with _sem:
            _pace(node_name)
            if node.get("type") == "local":
                body, tool = trace_local(host)
            else:
                body, tool = trace_remote(node, host)
        _store(name, node_name, host, body, tool, when)
        return {"target": name, "node": node_name, "ok": True,
                "seconds": round(time.time() - t0, 1), "error": None}
    except Exception as exc:
        return {"target": name, "node": node_name, "ok": False,
                "seconds": round(time.time() - t0, 1), "error": str(exc)}


def run_all() -> dict:
    """Trace every (target, node) pair once. Skips pairs that already have a
    trace for today. Returns a summary dict."""
    when = datetime.now(timezone.utc)
    today = when.strftime("%Y-%m-%d")
    pending = [(t, n) for t, n in _pairs()
               if latest_trace(t["name"], n["name"]) != today]
    if not pending:
        return {"ts": time.time(), "skipped": "already complete",
                "ok": 0, "failed": 0, "seconds": 0.0}

    results = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=max(1, _TRACE_CONCURRENCY)) as ex:
        futs = [ex.submit(_run_pair, t, n, when) for t, n in pending]
        for fut in futs:
            results.append(fut.result())
    ok = sum(1 for r in results if r["ok"])
    failed = [r for r in results if not r["ok"]]
    summary = {
        "ts": time.time(),
        "probes": len(results),
        "ok": ok,
        "failed": len(failed),
        "seconds": round(time.time() - t0, 1),
    }
    if failed:
        print("[traceroute] %d/%d traces failed:" % (len(failed), len(results)),
              file=sys.stderr)
        for r in failed[:20]:
            print("  %s <- %s: %s" % (r["target"], r["node"], r["error"]),
                  file=sys.stderr)
    print("[traceroute] run complete: %d ok, %d failed, %.0fs"
          % (ok, len(failed), summary["seconds"]), file=sys.stderr)
    return summary


# --- retention / archiving -------------------------------------------------

def _archive_month(month: str, files: list[tuple[str, str]]) -> None:
    """Merge files (loose_path, arcname) into archives/<month>.tar.gz."""
    os.makedirs(_ARCHIVE_DIR, exist_ok=True)
    arch_path = os.path.join(_ARCHIVE_DIR, month + ".tar.gz")
    existing: dict[str, bytes] = {}
    if os.path.exists(arch_path):
        with tarfile.open(arch_path, "r:gz") as tf:
            for m in tf.getmembers():
                if m.isfile():
                    fh = tf.extractfile(m)
                    if fh is not None:
                        existing[m.name] = fh.read()
    for loose, arcname in files:
        with open(loose, "rb") as fh:
            existing[arcname] = fh.read()
    tmp = arch_path + ".tmp"
    with tarfile.open(tmp, "w:gz") as tf:
        for name in sorted(existing):
            data = existing[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = int(time.time())
            tf.addfile(info, io.BytesIO(data))
    os.replace(tmp, arch_path)


def _enforce_archive_cap() -> None:
    if not os.path.isdir(_ARCHIVE_DIR):
        return
    entries = []
    for fname in os.listdir(_ARCHIVE_DIR):
        if not fname.endswith(".tar.gz"):
            continue
        path = os.path.join(_ARCHIVE_DIR, fname)
        entries.append((os.path.getmtime(path), os.path.getsize(path), path))
    total = sum(e[1] for e in entries)
    entries.sort()
    while total > _ARCHIVE_MAX_BYTES and entries:
        mtime, size, path = entries.pop(0)
        os.unlink(path)
        total -= size
        print("[traceroute] archive cap hit: removed %s (%d bytes)"
              % (os.path.basename(path), size), file=sys.stderr)


def apply_retention() -> dict:
    """Archive traces older than the retention window, then enforce the cap.

    Only runs when SMOKPING_TRACE_RETENTION_DAYS is set; with the default
    (unset) every trace stays loose on disk — unlimited, per the operator.
    Loose copies are deleted only after their month archive was written
    successfully.
    """
    if _TRACE_RETENTION_DAYS <= 0:
        return {"skipped": "retention not configured (unlimited)"}
    cutoff = (datetime.now(timezone.utc) - timedelta(days=_TRACE_RETENTION_DAYS)
              ).strftime("%Y-%m-%d")
    by_month: dict[str, list[tuple[str, str]]] = {}
    if os.path.isdir(TRACES_DIR):
        for tname in sorted(os.listdir(TRACES_DIR)):
            tdir = os.path.join(TRACES_DIR, tname)
            if not os.path.isdir(tdir):
                continue
            for nname in sorted(os.listdir(tdir)):
                pair_dir = os.path.join(tdir, nname)
                if not os.path.isdir(pair_dir):
                    continue
                for tfname in os.listdir(pair_dir):
                    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})\.txt", tfname)
                    if not m or m.group(1) >= cutoff:
                        continue
                    date = m.group(1)
                    loose = os.path.join(pair_dir, tfname)
                    arcname = "traces/%s/%s/%s" % (tname, nname, tfname)
                    by_month.setdefault(date[:7], []).append((loose, arcname))
    archived = 0
    for month, files in sorted(by_month.items()):
        try:
            _archive_month(month, files)
        except Exception:
            traceback.print_exc()
            continue  # loose copies stay: never delete what failed to archive
        touched_dirs = set()
        for loose, arcname in files:
            try:
                os.unlink(loose)
                archived += 1
                touched_dirs.add(os.path.dirname(loose))
            except OSError:
                pass
        for d in touched_dirs:
            try:
                os.rmdir(d)  # succeeds only when empty
            except OSError:
                pass
    _enforce_archive_cap()
    return {"archived": archived, "months": sorted(by_month)}


# --- thread ----------------------------------------------------------------

_stop = threading.Event()
_thread: Optional[threading.Thread] = None


def _scheduled_hm() -> tuple[int, int]:
    try:
        h, m = _TRACE_AT.split(":")
        return int(h) % 24, int(m) % 60
    except ValueError:
        return 4, 20


def _run_forever() -> None:
    h, m = _scheduled_hm()
    while not _stop.is_set():
        now = datetime.now(timezone.utc)
        run_at = now.replace(hour=h, minute=m, second=0, microsecond=0)
        if now >= run_at:
            # The scheduled time has passed today: run now if the day's
            # traces are missing (deploy catch-up, fresh boot, first run).
            if not _today_complete():
                try:
                    run_all()
                except Exception:
                    traceback.print_exc()
                try:
                    apply_retention()
                except Exception:
                    traceback.print_exc()
            run_at += timedelta(days=1)
        _stop.wait(max(30.0, (run_at - now).total_seconds()))


def start() -> None:
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_run_forever, name="smokeping-traceroute",
                               daemon=True)
    _thread.start()


def remove_target_files(target: str) -> None:
    """Drop a removed target's trace tree (called by the admin API)."""
    shutil.rmtree(os.path.join(TRACES_DIR, rrd._safe_name(target)),
                  ignore_errors=True)


if __name__ == "__main__":
    print(json.dumps(run_all(), indent=2))
    print(json.dumps(apply_retention(), indent=2))
