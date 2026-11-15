"""Ping runner for smokeping probes.

Local probes use the system ``ping`` binary. Remote probes run the same
``ping`` over SSH via paramiko (same pattern as wmon/backup_manager). Every
(target, node) probe returns a small result dict: min/avg/max rtt in ms,
packet loss percent, and an error string when the probe could not run.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import threading
import time
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))


class ProbeError(RuntimeError):
    """Raised when a probe cannot be executed or returns no usable data."""


# --- rate limiting ---------------------------------------------------------

# Bounded concurrency across all in-flight probes so a node never gets a probe
# storm, plus a per-node pacing lock so each node is probed at most once per
# PACE_INTERVAL seconds.
_CONCURRENCY = int(os.environ.get("SMOKPING_CONCURRENCY", "4"))
_PACE_INTERVAL = float(os.environ.get("SMOKPING_PACE_INTERVAL", "1.0"))

_sem = threading.Semaphore(_CONCURRENCY)
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


# --- ping parsing ----------------------------------------------------------

_PING_STATS = re.compile(
    r"([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms",
)


def _parse_ping_output(text: str) -> dict:
    """Parse ``ping`` output into min/avg/max mdev ms and loss percent."""
    loss = 100.0
    loss_match = re.search(r"(\d+(?:\.\d+)?)% packet loss", text)
    if loss_match:
        loss = float(loss_match.group(1))
    result = {"min": None, "avg": None, "max": None, "mdev": None, "loss": loss}
    stats = _PING_STATS.search(text)
    if stats:
        result["min"] = float(stats.group(1))
        result["avg"] = float(stats.group(2))
        result["max"] = float(stats.group(3))
        result["mdev"] = float(stats.group(4))
    return result


def _ips_for_host(host: str) -> list[str]:
    """Return candidate IPs for a host: the host itself if it's an IP, else
    the same-/24 neighbours resolved via socket.getaddrinfo."""
    candidates: list[str] = []
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        import socket

        seen: set[str] = set()
        for res in socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM):
            ip = res[4][0]
            if ":" in ip:
                continue  # IPv4 targets only for the /24 fallback logic
            if ip not in seen:
                seen.add(ip)
                candidates.append(ip)
    except OSError:
        pass
    return candidates


def _same_24_candidates(ip: str) -> list[str]:
    """Other usable addresses in the same /24 as ``ip`` (excluding .0 and .255)."""
    try:
        net = ipaddress.IPv4Network(ip + "/24", strict=False)
    except ValueError:
        return []
    out: list[str] = []
    for addr in net.hosts():
        s = str(addr)
        if s == ip:
            continue
        out.append(s)
    return out


# --- local ping ------------------------------------------------------------

def ping_local(host: str, count: int = 1, timeout: int = 3) -> dict:
    """Run the system ``ping`` binary locally against ``host``."""
    ping = shutil.which("ping")
    if ping is None:
        raise ProbeError("ping binary not found")
    try:
        out = subprocess.run(
            [ping, "-c", str(count), "-W", str(timeout), host],
            capture_output=True, text=True, timeout=count * timeout + 5,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise ProbeError(f"ping failed: {exc}") from exc
    text = out.stdout + out.stderr
    parsed = _parse_ping_output(text)
    if out.returncode != 0 and parsed["avg"] is None:
        raise ProbeError(text.strip() or "ping returned non-zero exit code")
    return parsed


# --- remote ping over SSH --------------------------------------------------

def _remote_ssh_key() -> Optional[str]:
    """Best-effort discovery of an SSH key for remote nodes."""
    cands = [
        "[REDACTED:server-path]",  # readable by smokeping user
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ed25519",
        "/root/.ssh/monitoring_key",
    ]
    for cand in cands:
        if os.path.exists(cand) and os.access(cand, os.R_OK):
            return cand
    return None


def ping_remote(node: dict, host: str, count: int = 1, timeout: int = 3) -> dict:
    """Run ``ping -c count -W timeout host`` on ``node`` over SSH via paramiko."""
    try:
        import paramiko  # type: ignore
    except ImportError as exc:
        raise ProbeError("paramiko not installed") from exc

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
        stdin, stdout, stderr = client.exec_command(
            f"ping -c {count} -W {timeout} {host}", timeout=count * timeout + 10
        )
        text = stdout.read().decode(errors="replace") + stderr.read().decode(errors="replace")
        rc = stdout.channel.recv_exit_status()
    except Exception as exc:  # paramiko raises many subtypes
        raise ProbeError(f"ssh to {ssh_host} failed: {exc}") from exc
    finally:
        client.close()

    parsed = _parse_ping_output(text)
    if rc != 0 and parsed["avg"] is None:
        raise ProbeError(text.strip() or f"ping on {ssh_host} exited {rc}")
    return parsed


# --- node/target pairing ---------------------------------------------------

def is_v6_target(target: dict) -> bool:
    """True when the target pings over IPv6: the host is an IPv6 literal, or
    the target is explicitly named as an IPv6 variant of another target."""
    try:
        return ipaddress.ip_address(target.get("host", "")).version == 6
    except ValueError:
        return "IPv6" in target.get("name", "")


def skip_pair(target: dict, node: dict) -> bool:
    """True when the (target, node) pair must not be probed.

    One rule today: a node without native IPv6 (``probe_v6: false`` in
    nodes.json — moses reaches v6 only through a tunnel, so a tunnel
    RTT would be an artifact, not a measurement) never probes IPv6 targets.
    """
    return is_v6_target(target) and not node.get("probe_v6", True)


# --- public API ------------------------------------------------------------

def probe_target(target: dict, node: dict, count: int = 1, timeout: int = 3) -> dict:
    """Probe ``target`` from ``node`` with rate limiting and /24 fallback.

    Returns a result dict with keys: target, node, host (the address that
    actually answered), min/avg/max/mdev ms, loss percent, ok (bool), error.
    """
    t0 = time.time()
    host = target["host"]
    node_name = node["name"]
    error = None
    result_host = host
    parsed: Optional[dict] = None

    # Try the configured host, then same-/24 fallbacks until one answers.
    candidates = [host]
    for ip in _ips_for_host(host):
        if ip != host and ip not in candidates:
            candidates.append(ip)
    for ip in _same_24_candidates(host):
        if ip not in candidates:
            candidates.append(ip)

    last_error = None
    for cand in candidates:
        try:
            with _sem:
                lock = _node_lock(node_name)
                with lock:
                    # pace: wait until PACE_INTERVAL has elapsed since this
                    # node's last probe started.
                    last = _node_last.get(node_name, 0.0)
                    wait = _PACE_INTERVAL - (time.time() - last)
                    if wait > 0:
                        time.sleep(wait)
                    _node_last[node_name] = time.time()
                if node.get("type") == "local":
                    parsed = ping_local(cand, count=count, timeout=timeout)
                else:
                    parsed = ping_remote(node, cand, count=count, timeout=timeout)
            result_host = cand
            break
        except ProbeError as exc:
            last_error = str(exc)
            continue

    if parsed is None:
        return {
            "target": target["name"],
            "host": host,
            "node": node_name,
            "ok": False,
            "error": last_error or "no candidate answered",
            "ts": t0,
        }

    return {
        "target": target["name"],
        "host": result_host,
        "node": node_name,
        "ok": True,
        "error": None,
        "min": parsed["min"],
        "avg": parsed["avg"],
        "max": parsed["max"],
        "mdev": parsed["mdev"],
        "loss": parsed["loss"],
        "ts": t0,
    }


def verify_target(target: dict, nodes: list[dict], count: int = 1) -> dict:
    """Verify ``target`` pings from at least one node (for add/import).

    Returns dict with keys: ok, host (address that answered), node (which node
    confirmed it), results (list of per-node probe results), error.
    """
    for node in nodes:
        if not node.get("enabled", True):
            continue
        res = probe_target(target, node)
        if res["ok"]:
            return {
                "ok": True,
                "host": res["host"],
                "node": node["name"],
                "results": [res],
                "error": None,
            }
    # None answered: collect all results for the report.
    all_results = []
    for node in nodes:
        if not node.get("enabled", True):
            continue
        all_results.append(probe_target(target, node))
    return {
        "ok": False,
        "host": target["host"],
        "node": None,
        "results": all_results,
        "error": "no node could ping this target (tried same-/24 fallbacks)",
    }
