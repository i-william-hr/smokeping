"""Bulk target import for smokeping.

Accepts a raw GitHub URL (or any URL) or an uploaded file, auto-detects the
format, parses candidate targets, verifies each one (ping + same-/24 fallback),
writes new targets to targets.json, and returns a per-target report.

Primary format (willgrz/Bash-smokeping "by country targets"):
    Austria
    TU Wien Wien gd.tuwien.ac.at
    TU Graz Graz 129.27.3.13
    Germany
    ...

A line that is a single word (no spaces) sets the current country context.
Target lines: ``<name> <city> <host/IP>`` (3 whitespace-separated tokens).
``#`` comments and blank lines are skipped.

Fallback formats: plain text (one host/IP per line), CSV
(``name,host[,country]``), JSON (array of ``{name,host,country?}`` or strings).
"""

from __future__ import annotations

import csv
import io
import json
import os
from typing import Optional

import requests

from probe import verify_target

HERE = os.path.dirname(os.path.abspath(__file__))
TARGETS_PATH = os.path.join(HERE, "targets.json")


def _load_targets() -> list[dict]:
    try:
        with open(TARGETS_PATH) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


def _save_targets(targets: list[dict]) -> None:
    with open(TARGETS_PATH, "w") as fh:
        json.dump(targets, fh, indent=2)
        fh.write("\n")


def _target_key(t: dict) -> tuple:
    return (t.get("name", "").strip().lower(), t.get("host", "").strip().lower())


def _fetch_url(url: str) -> str:
    try:
        resp = requests.get(url, timeout=20, headers={"User-Agent": "smokeping-import/1.0"})
        resp.raise_for_status()
        return resp.text
    except Exception as exc:  # requests raises many subtypes
        raise RuntimeError(f"could not fetch {url}: {exc}") from exc


# --- format detectors / parsers -------------------------------------------

def _looks_country_line(line: str) -> bool:
    """A country header line: single whitespace-delimited token, no digits, no dots."""
    line = line.strip()
    if not line or line.startswith("#"):
        return False
    parts = line.split()
    if len(parts) != 1:
        return False
    token = parts[0]
    if any(ch.isdigit() for ch in token):
        return False
    if "." in token or "/" in token:
        return False
    return True


def parse_country_sectioned(text: str) -> list[dict]:
    """Parse the willgrz-style country-sectioned format."""
    targets: list[dict] = []
    country = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if _looks_country_line(line):
            country = line
            continue
        parts = line.split()
        if len(parts) >= 3:
            # name may contain spaces; last two tokens are city and host/IP.
            # e.g. "TU Wien Wien gd.tuwien.ac.at" -> name="TU Wien", city="Wien",
            # host="gd.tuwien.ac.at"
            name = " ".join(parts[:-2])
            city = parts[-2]
            host = parts[-1]
            targets.append({
                "name": name,
                "host": host,
                "country": country or "",
                "source": "import",
            })
        elif len(parts) == 2:
            # name host (no city)
            targets.append({
                "name": parts[0],
                "host": parts[1],
                "country": country or "",
                "source": "import",
            })
    return targets


def parse_plain(text: str) -> list[dict]:
    """One host/IP per line."""
    targets = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # skip country-sectioned looking content
        if _looks_country_line(line):
            continue
        targets.append({
            "name": line,
            "host": line,
            "country": "",
            "source": "import",
        })
    return targets


def parse_csv(text: str) -> list[dict]:
    targets = []
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        return targets
    # Detect header row
    first = rows[0]
    headerish = any(c.strip().lower() in ("name", "host", "country") for c in first)
    start = 1 if headerish else 0
    for row in rows[start:]:
        row = [c.strip() for c in row if c.strip()]
        if not row:
            continue
        name = row[0] if len(row) > 0 else row[-1]
        host = row[1] if len(row) > 1 else row[0]
        country = row[2] if len(row) > 2 else ""
        targets.append({
            "name": name,
            "host": host,
            "country": country,
            "source": "import",
        })
    return targets


def parse_json(text: str) -> list[dict]:
    targets = []
    data = json.loads(text)
    if isinstance(data, dict):
        data = [data]
    for item in data:
        if isinstance(item, str):
            targets.append({"name": item, "host": item, "country": "", "source": "import"})
        elif isinstance(item, dict):
            targets.append({
                "name": item.get("name", item.get("host", "")),
                "host": item.get("host", item.get("name", "")),
                "country": item.get("country", ""),
                "source": "import",
            })
    return targets


def detect_format(text: str) -> str:
    """Auto-detect format: 'country-sectioned', 'csv', 'json', 'plain'."""
    stripped = text.lstrip()
    if stripped.startswith("["):
        return "json"
    # CSV heuristic: header row contains name/host/country
    first_line = stripped.split("\n", 1)[0].strip()
    if any(c in first_line.lower() for c in ("name", "host", "country")) and "," in first_line:
        return "csv"
    # Country-sectioned: first non-comment line looks like a country
    for raw in stripped.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if _looks_country_line(line):
            return "country-sectioned"
        break
    return "plain"


def parse_import(text: str) -> list[dict]:
    fmt = detect_format(text)
    if fmt == "json":
        return parse_json(text)
    if fmt == "csv":
        return parse_csv(text)
    if fmt == "country-sectioned":
        return parse_country_sectioned(text)
    return parse_plain(text)


# --- public API -----------------------------------------------------------

def import_from_url(url: str, nodes: list[dict]) -> dict:
    """Fetch ``url``, parse, verify, import. Returns a report dict."""
    text = _fetch_url(url)
    return import_text(text, nodes)


def import_text(text: str, nodes: list[dict]) -> dict:
    """Parse text, verify each target, import new ones. Returns report dict."""
    candidates = parse_import(text)
    existing = _load_targets()
    existing_keys = {_target_key(t) for t in existing}

    report = {
        "format": detect_format(text),
        "candidates": len(candidates),
        "added": [],
        "already_present": [],
        "failed": [],
        "error": None,
    }

    newly_added: list[dict] = []
    for cand in candidates:
        key = _target_key(cand)
        if key in existing_keys:
            report["already_present"].append(cand)
            continue
        verification = verify_target(cand, nodes)
        if verification["ok"]:
            cand["host"] = verification["host"]
            cand["source"] = "import"
            newly_added.append(cand)
            existing_keys.add(key)
            report["added"].append({
                "name": cand["name"],
                "host": cand["host"],
                "country": cand.get("country", ""),
                "verified_from": verification["node"],
            })
        else:
            report["failed"].append({
                "name": cand["name"],
                "host": cand["host"],
                "country": cand.get("country", ""),
                "error": verification["error"],
            })

    if newly_added:
        combined = existing + newly_added
        _save_targets(combined)

    return report
