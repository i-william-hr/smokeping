"""Smokeping web service — public graphs + gated admin.

Public (no auth):
    GET /                       target list + latest latency per probe node
    GET /graphs/<target>__<node>.png   RRD graph PNG (24h/7d/30d/1y)
    GET /traces/                traceroute index: every target × node
    GET /traces/<target>/       trace history for one target (dates × nodes)
    GET /traces/<target>/<node>    latest trace of a pair, rendered
    GET /traces/<target>/<node>/<date>.txt   raw trace (text/plain)

Admin (nginx enforces VPN IP ACL + SSO; app re-checks SMOKPING_ADMIN_TOKEN):
    GET  /admin/                admin dashboard (targets + nodes)
    GET  /admin/api/targets     JSON target list
    GET  /admin/api/nodes       JSON node list
    GET  /admin/api/latest      JSON latest values per (target, node)
    GET  /admin/api/summary     JSON scheduler summary
    POST /admin/api/targets     add a target  (json {name,host,country?})
    POST /admin/api/targets/<name>   remove a target
    POST /admin/api/nodes       add a node    (json {name,host,type,ssh_user,ssh_port})
    POST /admin/api/nodes/<name>     remove a node
    POST /admin/api/nodes/<name>/backlog   trigger immediate backlog from a node
    POST /admin/api/verify      verify a target pings (json {host,name?,country?})
    POST /admin/api/import      bulk import (json {url} or multipart file)
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import time

from flask import (
    Flask, jsonify, render_template_string, request, send_from_directory,
)

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def _load_dotenv(path=os.path.join(HERE, ".env")):
    try:
        with open(path) as fh:
            lines = fh.read().splitlines()
    except FileNotFoundError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip())


# Must run BEFORE importing probe/scheduler/traceroute: those modules read
# their SMOKPING_* configuration at import time, so a .env value loaded later
# would silently never apply.
_load_dotenv()

import probe
import rrd
import scheduler as scheduler_mod
import traceroute as traceroute_mod
import importlib.util
_spec = importlib.util.spec_from_file_location("smokeping_import", os.path.join(HERE, "import.py"))
import_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(import_mod)

app = Flask(__name__)

BIND_IP = os.environ.get("SMOKPING_BIND_IP", "127.0.0.1")
BIND_PORT = int(os.environ.get("SMOKPING_BIND_PORT", "[REDACTED:loopback-port]"))
ADMIN_TOKEN = os.environ.get("SMOKPING_ADMIN_TOKEN", "")

# start the background scheduler
scheduler_mod.scheduler.start()
# and the daily traceroute thread (catches up on today's traces at startup)
traceroute_mod.start()


# ------------------------------------------------------------------ helpers

def _admin_ok() -> bool:
    """App-level admin gate: nginx already enforced VPN + SSO; we re-check the
    per-app token so the admin surface is not reachable by anyone past nginx."""
    token = request.headers.get("X-SMOKEPING-ADMIN-TOKEN") or request.headers.get(
        "X-SSO-Gate-Token")
    return bool(ADMIN_TOKEN) and token == ADMIN_TOKEN


def _admin_required():
    if not _admin_ok():
        return jsonify({"error": "admin access denied"}), 403
    return None


def _targets():
    path = os.path.join(HERE, "targets.json")
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


def _save_targets(targets):
    path = os.path.join(HERE, "targets.json")
    with open(path, "w") as fh:
        json.dump(targets, fh, indent=2)
        fh.write("\n")


def _nodes():
    path = os.path.join(HERE, "nodes.json")
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


def _save_nodes(nodes):
    path = os.path.join(HERE, "nodes.json")
    with open(path, "w") as fh:
        json.dump(nodes, fh, indent=2)
        fh.write("\n")


def _esc(s):
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ------------------------------------------------------------------ public

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Smokeping — ping.inbox.li</title>
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<link rel="icon" type="image/x-icon" href="/static/favicon.ico">
<style>
:root { --bg:#0b0f14; --card:#0f1720; --text:#e6eef6; --muted:#9aa4b2;
        --ok:#8ef3a0; --bad:#ff8b8b; --line:#1f2937; }
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--text); font-family: system-ui,-apple-system,Segoe UI,Roboto,sans-serif; margin:0; padding:24px; }
h1 { font-size: 20px; margin: 0 0 8px 0; display:flex; align-items:center; gap:10px; }
.sub { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
.grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 14px; }
.card h2 { font-size: 15px; margin: 0 0 8px 0; border-bottom: 1px solid var(--line); padding-bottom: 6px; }
.meta { font-size: 12px; color: var(--muted); margin-bottom: 10px; display:flex; gap:16px; flex-wrap:wrap; }
.graph img { display: block; width: 100%; height: auto; border-radius: 6px; background:#070a0d; }
.footer { margin-top: 30px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--line); padding-top: 12px; }
.ok { color: var(--ok); } .bad { color: var(--bad); } .unk { color: #e8c36a; }
.admin-link { color: var(--muted); font-size: 12px; }
.admin-link a { color: #6fa3dc; text-decoration: none; }
.admin-link a:hover { text-decoration: underline; }
</style>
</head>
<body>
<h1>📉 Smokeping <span style="font-size:14px;font-weight:normal;color:var(--muted)">ping.inbox.li</span></h1>
<div class="sub">Latency over time, probed locally (negev) and from Moses (NL) over the WireGuard tunnel. Public to view — no login required.</div>

<div class="btnrow" style="margin-bottom:14px; display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
  <button class="setall" data-node="negev">All graphs → negev</button>
  <button class="setall" data-node="moses">All graphs → moses</button>
  <span style="color:var(--muted);font-size:12px;margin-left:auto;">One graph per target — click a node stat to set that card’s graph</span>
  <label style="color:var(--muted);font-size:12px;margin-left:12px;">Country:
  <select id="countryFilter" onchange="filterCountry(this.value)" style="background:#070a0d;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:4px 8px;font-size:12px;">
    <option value="">All countries</option>
{% for c in countries %}
    <option value="{{ _esc(c) }}">{{ _esc(c) }}</option>
{% endfor %}
  </select>
  </label>
</div>

<div class="grid">
{% for group in groups %}
<div class="card" data-country="{{ _esc(group.country) }}">
<h2>{{ _esc(group.target) }}</h2>
<div class="meta"><span><b>country:</b> {{ _esc(group.country) }}</span>
<span><b>host:</b> {{ _esc(group.host) }}</span>
<span><a href="/traces/{{ safe(group.target) }}/" style="color:#6fa3dc">traceroutes</a></span></div>
<div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom:8px;">
{% for node in group.nodes %}
<div class="node-box" data-node="{{ _esc(node.name) }}" style="border:1px solid var(--line); border-radius:6px; padding:6px 10px; min-width:150px; cursor:pointer;">
<div style="font-size:11px;color:var(--muted)">{{ _esc(node.name) }}
  <a href="/traces/{{ safe(group.target) }}/{{ safe(node.name) }}" style="color:#6fa3dc" onclick="event.stopPropagation()">trace</a></div>
<div style="font-size:13px;font-family:monospace">
{% if node.ok is not none %}
<span class="{{ 'ok' if node.ok else 'bad' }}">{% if node.ok %}{{ '%.2f ms'|format(node.avg) }}{% else %}--{% endif %}</span>
{% if node.loss is not none %} ({{ '%.0f%%'|format(node.loss) }} loss){% endif %}
{% else %}<span class="unk">no data</span>{% endif %}
</div>
</div>
{% endfor %}
</div>
<div class="graph">
{% set primary = group.nodes[0] if group.nodes else None %}
{% if primary %}
<img src="/graphs/{{ safe(group.target) }}__{{ safe(primary.name) }}__24h.png" alt="{{ _esc(group.target) }} from {{ _esc(primary.name) }}" style="width:100%; height:auto; display:block;">
<div style="font-size:11px;color:var(--muted);margin-top:4px;text-align:center">{{ _esc(primary.name) }} · 24h</div>
{% endif %}
</div>
</div>
{% endfor %}
</div>

<script>
function safe(s){ return String(s).replace(/[^A-Za-z0-9\-_. ]/g,"_").trim(); }
function setCardGraph(card, node){
  var graphDiv = card.querySelector('.graph');
  var target = card.querySelector('h2').textContent.trim();
  var img = graphDiv.querySelector('img');
  var cap = graphDiv.querySelector('div');
  img.src = '/graphs/' + safe(target) + '__' + safe(node) + '__24h.png';
  cap.textContent = node + ' · 24h';
}
function filterCountry(v){
  document.querySelectorAll('.card').forEach(function(c){
    c.style.display = (!v || c.dataset.country === v) ? '' : 'none';
  });
}
document.querySelectorAll('.node-box').forEach(function (box) {
  box.addEventListener('click', function () {
    var card = this.closest('.card');
    setCardGraph(card, this.dataset.node);
  });
});
document.querySelectorAll('.setall').forEach(function (btn) {
  btn.addEventListener('click', function () {
    var node = this.dataset.node;
    document.querySelectorAll('.card').forEach(function (card){
      setCardGraph(card, node);
    });
  });
});
</script>

{% if not groups %}
<div class="card"><p style="color:var(--muted)">No targets yet. Add targets via <code>/admin</code>.</p></div>
{% endif %}

<div class="footer admin-link">
<a href="/admin/">Admin (add/remove targets &amp; nodes, bulk import)</a> — VPN + SSO required.
</div>
<div class="footer">Smokeping on negev-no-1 · <a style="color:#6fa3dc" href="/api/latest">json</a></div>
</body>
</html>"""


@app.route("/")
def index():
    targets = _targets()
    nodes = [n for n in _nodes() if n.get("enabled", True)]
    # latest values per (target, node)
    groups = []
    for t in targets:
        g = {"target": t["name"], "host": t["host"], "country": t.get("country", ""), "nodes": []}
        for n in nodes:
            lat = rrd.latest(t["name"], n["name"])
            g["nodes"].append({
                "name": n["name"],
                "ok": bool(lat and lat.get("avg") is not None),
                "avg": lat.get("avg") if lat else None,
                "loss": lat.get("loss") if lat else None,
            })
        groups.append(g)
    countries = sorted({g["country"] for g in groups if g.get("country")})
    return render_template_string(
        INDEX_HTML, groups=groups, countries=countries,
        _esc=_esc, safe=rrd._safe_name)


@app.route("/graphs/<path:fname>.png")
def graph_png(fname):
    # fname is "target__node__window" (window in the path so nginx can map the
    # URL straight to the cached file on disk and only fall through to the app
    # for graphs that don't exist yet). "?w=" still accepted for compatibility.
    known = {"24h", "7d", "30d", "1y"}
    if "__" not in fname:
        return "bad graph name", 400
    rest, _, tail = fname.rpartition("__")
    if tail in known and rest:
        window, target_node = tail, rest
    else:
        window, target_node = request.args.get("w", "24h"), fname
    if "__" not in target_node:
        return "bad graph name", 400
    target, node = target_node.split("__", 1)
    # graph_rrd returns the cached PNG when it is at least as new as the RRD
    # and re-renders otherwise, so any request that reaches the app (nginx
    # try_files miss on a not-yet-existing graph, or a direct hit) is answered
    # with a fresh render rather than a stale file.
    path = rrd.graph_rrd(target, node, window)
    if not path or not os.path.exists(path):
        return "no graph", 404
    return send_from_directory(os.path.dirname(path), os.path.basename(path),
                               mimetype="image/png")


# ------------------------------------------------------------------ traces

TRACE_CSS = """
:root { --bg:#0b0f14; --card:#0f1720; --text:#e6eef6; --muted:#9aa4b2;
        --line:#1f2937; --accent:#6fa3dc; }
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--text); font-family: system-ui,-apple-system,Segoe UI,Roboto,sans-serif; margin:0; padding:24px; }
h1 { font-size: 20px; margin: 0 0 6px 0; }
.sub { color: var(--muted); font-size: 13px; margin-bottom: 20px; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.grid { display: grid; grid-template-columns: repeat(auto-fill,minmax(360px,1fr)); gap: 14px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
.card h2 { font-size: 14px; margin: 0 0 6px 0; }
.meta { font-size: 11px; color: var(--muted); margin-bottom: 6px; }
.node { font-size: 12px; font-family: monospace; }
.none { color: var(--muted); font-style: italic; }
table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--line); font-family: monospace; }
th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
pre { background: #070a0d; border: 1px solid var(--line); border-radius: 8px; padding: 14px; font-size: 12.5px; line-height: 1.5; overflow: auto; max-width: 100%; }
.footer { margin-top: 24px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--line); padding-top: 10px; }
"""


def _trace_name_maps():
    """safe-name -> original-name maps for validating /traces/ URLs.

    The filesystem (and the URLs) use rrd._safe_name forms; anything not in
    these maps is a 404, which also kills any path-traversal attempt.
    """
    tmap = {rrd._safe_name(t["name"]): t["name"] for t in _targets()}
    nmap = {rrd._safe_name(n["name"]): n["name"]
            for n in _nodes() if n.get("enabled", True)}
    return tmap, nmap


@app.route("/traces/")
def traces_global():
    tmap, nmap = _trace_name_maps()
    rows = []
    for tsafe in sorted(tmap):
        entry = {"safe": tsafe, "name": tmap[tsafe], "nodes": []}
        for nsafe in sorted(nmap):
            entry["nodes"].append({
                "safe": nsafe, "name": nmap[nsafe],
                "latest": traceroute_mod.latest_trace(tmap[tsafe], nmap[nsafe]),
            })
        rows.append(entry)
    return render_template_string(r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Traceroutes — ping.inbox.li</title>
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<link rel="icon" type="image/x-icon" href="/static/favicon.ico">
<style>{{ css }}</style>
</head>
<body>
<h1>🗺️ Traceroutes <span style="font-size:14px;font-weight:normal;color:var(--muted)">ping.inbox.li</span></h1>
<div class="sub">One trace per target and probe node per day ({{ trace_at }} UTC). Leading private/VPN hops are stripped; internal addresses are masked. <a href="/">← back to the graphs</a></div>
<div class="grid">
{% for t in rows %}
<div class="card">
<h2><a href="/traces/{{ t.safe }}/">{{ _esc(t.name) }}</a></h2>
{% for n in t.nodes %}
<div class="node">{{ _esc(n.name) }}:
{% if n.latest %}<a href="/traces/{{ t.safe }}/{{ n.safe }}">{{ n.latest }}</a>
 · <a href="/traces/{{ t.safe }}/{{ n.safe }}/{{ n.latest }}.txt">raw</a>
{% else %}<span class="none">no trace yet</span>{% endif %}
</div>
{% endfor %}
</div>
{% endfor %}
</div>
<div class="footer">Traces run daily inside smokeping.service. When trace retention is configured, older traces are archived to the traceping ZFS dataset (capped at 1&nbsp;GB) and removed from this index.</div>
</body>
</html>""", css=TRACE_CSS, rows=rows, trace_at=traceroute_mod._TRACE_AT, _esc=_esc)


@app.route("/traces/<target>/")
def traces_history(target):
    tmap, nmap = _trace_name_maps()
    if target not in tmap:
        return "unknown target", 404
    tname = tmap[target]
    nodes = []
    all_dates = set()
    for nsafe in sorted(nmap):
        dates = traceroute_mod.list_dates(tname, nmap[nsafe])
        all_dates.update(dates)
        nodes.append({"safe": nsafe, "name": nmap[nsafe], "dates": set(dates)})
    return render_template_string(r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ _esc(tname) }} — trace history</title>
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<link rel="icon" type="image/x-icon" href="/static/favicon.ico">
<style>{{ css }}</style>
</head>
<body>
<h1>🗺️ {{ _esc(tname) }} — trace history</h1>
<div class="sub"><a href="/traces/">← all traceroutes</a> · <a href="/">graphs</a>
 · latest trace per node:
{% for n in nodes %} {% if n.dates %}<a href="/traces/{{ target }}/{{ n.safe }}">{{ _esc(n.name) }}</a>{% else %}<span class="none">{{ _esc(n.name) }} (none)</span>{% endif %}{% endfor %}
</div>
{% if dates %}
<table>
<thead><tr><th>date</th>{% for n in nodes %}<th>{{ _esc(n.name) }}</th>{% endfor %}</tr></thead>
<tbody>
{% for d in dates %}
<tr><td>{{ d }}</td>
{% for n in nodes %}<td>{% if d in n.dates %}<a href="/traces/{{ target }}/{{ n.safe }}/{{ d }}.txt">view</a>{% else %}<span class="none">—</span>{% endif %}</td>{% endfor %}
</tr>
{% endfor %}
</tbody>
</table>
{% else %}
<div class="card"><span class="none">No traces yet. The daily run happens at {{ trace_at }} UTC (and on service start if today's traces are missing).</span></div>
{% endif %}
<div class="footer">Leading private/VPN hops are stripped from every trace; internal addresses are masked as &lt;internal&gt;.</div>
</body>
</html>""", css=TRACE_CSS, target=target, tname=tname, nodes=nodes,
        dates=sorted(all_dates, reverse=True), trace_at=traceroute_mod._TRACE_AT,
        _esc=_esc)


@app.route("/traces/<target>/<node>")
def traces_pair(target, node):
    tmap, nmap = _trace_name_maps()
    if target not in tmap or node not in nmap:
        return "unknown target or node", 404
    tname, nname = tmap[target], nmap[node]
    date = traceroute_mod.latest_trace(tname, nname)
    text = traceroute_mod.read_trace(tname, nname, date) if date else None
    return render_template_string(r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ _esc(tname) }} ← {{ _esc(nname) }} — trace</title>
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<link rel="icon" type="image/x-icon" href="/static/favicon.ico">
<style>{{ css }}</style>
</head>
<body>
<h1>🗺️ {{ _esc(tname) }} <span style="color:var(--muted)">from</span> {{ _esc(nname) }}</h1>
<div class="sub">
{% if text %}
latest trace: <b>{{ date }}</b> · <a href="/traces/{{ target }}/{{ node }}/{{ date }}.txt">raw</a> · <a href="/traces/{{ target }}/">history</a> · <a href="/">graphs</a>
{% else %}
<span class="none">No trace yet — the daily run happens at {{ trace_at }} UTC (and on service start if today's traces are missing).</span> · <a href="/traces/{{ target }}/">history</a> · <a href="/">graphs</a>
{% endif %}
</div>
{% if text %}<pre>{{ _esc(text) }}</pre>{% endif %}
<div class="footer">Leading private/VPN hops are stripped; internal addresses are masked as &lt;internal&gt;.</div>
</body>
</html>""", css=TRACE_CSS, target=target, node=node, tname=tname, nname=nname,
        date=date, text=text, trace_at=traceroute_mod._TRACE_AT, _esc=_esc)


@app.route("/traces/<target>/<node>/<date>.txt")
def traces_raw(target, node, date):
    tmap, nmap = _trace_name_maps()
    if target not in tmap or node not in nmap:
        return "unknown target or node", 404
    path = traceroute_mod.trace_path(tmap[target], nmap[node], date)
    if path is None:
        return "no such trace", 404
    return send_from_directory(os.path.dirname(path), os.path.basename(path),
                               mimetype="text/plain; charset=utf-8")


@app.route("/api/latest")
def api_latest():
    out = {}
    for t in _targets():
        out.setdefault(t["name"], {})
        for n in _nodes():
            out[t["name"]][n["name"]] = rrd.latest(t["name"], n["name"])
    return jsonify(out)


# ------------------------------------------------------------------ admin

ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Smokeping Admin — ping.inbox.li</title>
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<link rel="icon" type="image/x-icon" href="/static/favicon.ico">
<style>
:root { --bg:#0b0f14; --card:#0f1720; --text:#e6eef6; --muted:#9aa4b2;
        --line:#1f2937; --ok:#8ef3a0; --bad:#ff8b8b; --accent:#6fa3dc; }
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--text); font-family: system-ui,-apple-system,Segoe UI,Roboto,sans-serif; margin:0; padding:24px; }
h1 { font-size: 20px; margin: 0 0 6px 0; }
.sub { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
a.back { color: var(--accent); text-decoration: none; font-size: 13px; }
a.back:hover { text-decoration: underline; }
.grid { display: grid; grid-template-columns: repeat(auto-fill,minmax(460px,1fr)); gap: 20px; margin-bottom: 26px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 16px; }
.card h2 { font-size: 15px; margin: 0 0 12px 0; border-bottom: 1px solid var(--line); padding-bottom: 8px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
tr:hover { background: rgba(255,255,255,0.03); }
.ok { color: var(--ok); } .bad { color: var(--bad); } .unk { color: #e8c36a; }
form { display: grid; grid-template-columns: 1fr auto; gap: 8px; margin: 14px 0; }
input, textarea, select { background: #070a0d; border: 1px solid var(--line); color: var(--text); border-radius: 6px; padding: 8px 10px; font-size: 13px; }
input:focus { border-color: var(--accent); outline: none; }
button { background: var(--accent); color: #000; border: none; border-radius: 6px; padding: 8px 14px; font-size: 13px; cursor: pointer; font-weight: 600; }
button:hover { opacity: 0.9; }
button.secondary { background: #1f2937; color: var(--text); }
button.danger { background: var(--bad); color: #000; }
label { font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px; }
pre { background: #070a0d; border: 1px solid var(--line); border-radius: 6px; padding: 10px; font-size: 12px; overflow: auto; max-width: 100%; }
.section-title { font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; margin: 20px 0 8px 0; }
.tip { color: var(--muted); font-size: 12px; margin-top: 6px; }
</style>
</head>
<body>
<h1>⚙️ Smokeping Admin</h1>
<div class="sub"><a class="back" href="/">&larr; back to public view</a> · VPN + SSO required · {{ _esc(total_targets) }} targets · {{ _esc(total_nodes) }} nodes</div>

<h2>Targets</h2>
<div class="grid">
<div class="card">
<table>
<thead><tr><th>Name</th><th>Host</th><th>Country</th><th>Source</th><th></th></tr></thead>
<tbody>
{% for t in targets %}
<tr>
<td>{{ _esc(t.name) }}</td>
<td style="font-family:monospace">{{ _esc(t.host) }}</td>
<td>{{ _esc(t.get('country','')) }}</td>
<td style="font-size:11px;color:var(--muted)">{{ _esc(t.get('source','')) }}</td>
<td><button class="danger secondary" onclick="delTarget('{{ _esc(t.name) }}')">remove</button></td>
</tr>
{% endfor %}
{% if not targets %}
<tr><td colspan="5" style="color:var(--muted)">No targets.</td></tr>
{% endif %}
</tbody>
</table>
</div>
</div>

<div class="section-title">Add target</div>
<form id="addTargetForm">
<div style="display:contents;">
<label>Name <input name="name" placeholder="TU Wien" required></label>
<label>Host <input name="host" placeholder="gd.tuwien.ac.at" required></label>
<label>Country <input name="country" placeholder="Austria"></label>
<button type="submit">Add</button>
</div>
</form>
<div class="tip">Verify pings before adding. If the host doesn't answer, smokeping tries other IPs in the same /24; if none answer, you'll be asked to supply an IP or remove the ISP.</div>

<h2 id="import">Bulk import (from GitHub raw URL or file)</h2>
<div class="grid">
<div class="card">
<form id="importUrlForm">
<label style="margin-bottom:6px">Raw URL (e.g. https://raw.githubusercontent.com/user/repo/branch/list.txt)</label>
<input name="url" placeholder="https://raw.githubusercontent.com/..." style="grid-column:1/-1;" required>
<button type="submit">Import from URL</button>
</form>
<div class="tip">Accepted: willgrz-style country-sectioned lists (<code>Country</code> then <code>name city host</code>), plain text, CSV, JSON.</div>
</div>
<div class="card">
<form id="importFileForm" enctype="multipart/form-data">
<label style="margin-bottom:6px">Or upload a file</label>
<input name="file" type="file" required>
<button type="submit">Import file</button>
</form>
</div>
</div>

<h2>Probe Nodes</h2>
<div class="grid">
<div class="card">
<table>
<thead><tr><th>Name</th><th>Host</th><th>Type</th><th>Enabled</th><th></th></tr></thead>
<tbody>
{% for n in nodes %}
<tr>
<td>{{ _esc(n.name) }}</td>
<td style="font-family:monospace">{{ _esc(n.host) }}</td>
<td style="font-size:11px;color:var(--muted)">{{ _esc(n.get('type','')) }}</td>
<td>{{ 'yes' if n.get('enabled',True) else 'no' }}</td>
<td><button class="danger secondary" onclick="delNode('{{ _esc(n.name) }}')">remove</button></td>
</tr>
{% endfor %}
{% if not nodes %}
<tr><td colspan="5" style="color:var(--muted)">No nodes.</td></tr>
{% endif %}
</tbody>
</table>
</div>
</div>

<div class="section-title">Add probe node</div>
<form id="addNodeForm">
<div style="display:contents;">
<label>Name <input name="name" placeholder="moses" required></label>
<label>Host <input name="host" placeholder="[REDACTED:internal-ipv4]" required></label>
<label>Type <select name="type"><option value="local">local</option><option value="remote">remote (SSH)</option></select></label>
<label>SSH user <input name="ssh_user" placeholder="root"></label>
<label>SSH port <input name="ssh_port" placeholder="22" value="22"></label>
<button type="submit">Add node</button>
</div>
</form>
<div class="tip">New nodes immediately begin a rate-limited backlog probe of all targets.</div>

<div id="result" style="margin-top:16px;"></div>

<script>
async function postJSON(path, body){
  const r = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  return {ok: r.ok, json: await r.json().catch(()=>({})), status: r.status};
}
function show(html){ document.getElementById('result').innerHTML = html; }
function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}

document.getElementById('addTargetForm').onsubmit = async (e)=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = {name: fd.get('name'), host: fd.get('host'), country: fd.get('country')};
  const r = await postJSON('/admin/api/targets', body);
  if (r.ok) { show('<p class="ok">Added '+esc(body.name)+' → '+esc(body.host)+' (verified from '+r.json.verified_from+')</p>'); e.target.reset(); location.reload(); }
  else { show('<p class="bad">Failed: '+esc((r.json&&r.json.error)||r.status)+'</p>'); }
};

async function delTarget(name){
  if(!confirm('Remove target '+esc(name)+'?')) return;
  const r = await fetch('/admin/api/targets/'+encodeURIComponent(name), {method:'POST'});
  const j = await r.json().catch(()=>({}));
  show('<p class="'+(r.ok?'ok':'bad')+'">'+esc((j&&j.message)||r.status)+'</p>'); location.reload();
}

document.getElementById('importUrlForm').onsubmit = async (e)=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  const r = await postJSON('/admin/api/import', {url: fd.get('url')});
  showImportResult(r);
};

document.getElementById('importFileForm').onsubmit = async (e)=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  const r = await fetch('/admin/api/import', {method:'POST', body: fd});
  const j = await r.json().catch(()=>({}));
  show({ok:r.ok, json:j, status:r.status});
};

function showImportResult(r){
  const j = r.json||{};
  let h = '';
  if (!r.ok) { h = '<p class="bad">Import failed: '+esc((j&&j.error)||r.status)+'</p>'; }
  else {
    h += '<p class="ok">Imported '+esc(j.format)+' format: '+esc(j.candidates)+' candidates.</p>';
    if (j.added.length) {
      h += '<p class="ok">Added '+esc(j.added.length)+':</p><ul>';
      for (const a of j.added) h += '<li>'+esc(a.name)+' → '+esc(a.host)+' (from '+esc(a.verified_from)+')</li>';
      h += '</ul>';
    }
    if (j.already_present.length) {
      h += '<p class="unk">Already present '+esc(j.already_present.length)+':</p><ul>';
      for (const a of j.already_present) h += '<li>'+esc(a.name)+' → '+esc(a.host)+'</li>';
      h += '</ul>';
    }
    if (j.failed.length) {
      h += '<p class="bad">Failed '+esc(j.failed.length)+':</p><ul>';
      for (const f of j.failed) h += '<li>'+esc(f.name)+' → '+esc(f.host)+': '+esc(f.error)+'</li>';
      h += '</ul>';
    }
  }
  show(h);
  if (r.ok) location.reload();
}

document.getElementById('addNodeForm').onsubmit = async (e)=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = {
    name: fd.get('name'), host: fd.get('host'), type: fd.get('type'),
    ssh_user: fd.get('ssh_user')||null, ssh_port: parseInt(fd.get('ssh_port')||'22')||22
  };
  const r = await postJSON('/admin/api/nodes', body);
  if (r.ok) { show('<p class="ok">Node '+esc(body.name)+' added — backlog starting.</p>'); e.target.reset(); location.reload(); }
  else { show('<p class="bad">Failed: '+esc((r.json&&r.json.error)||r.status)+'</p>'); }
};

async function delNode(name){
  if(!confirm('Remove node '+esc(name)+'?')) return;
  const r = await fetch('/admin/api/nodes/'+encodeURIComponent(name), {method:'POST'});
  const j = await r.json().catch(()=>({}));
  show('<p class="'+(r.ok?'ok':'bad')+'">'+esc((j&&j.message)||r.status)+'</p>'); location.reload();
}
</script>
</body>
</html>"""


def _admin_response(payload, status=200):
    return jsonify(payload), status


@app.route("/admin/")
def admin():
    if not _admin_ok():
        return jsonify({"error": "admin access denied"}), 403
    return render_template_string(
        ADMIN_HTML,
        targets=_targets(),
        nodes=_nodes(),
        total_targets=len(_targets()),
        total_nodes=len(_nodes()),
        _esc=_esc,
    )


@app.route("/admin/api/targets", methods=["GET"])
def admin_list_targets():
    if not _admin_ok():
        return jsonify({"error": "admin access denied"}), 403
    return jsonify(_targets())


@app.route("/admin/api/targets", methods=["POST"])
def admin_add_target():
    if not _admin_ok():
        return jsonify({"error": "admin access denied"}), 403
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    host = (body.get("host") or "").strip()
    country = (body.get("country") or "").strip()
    if not name or not host:
        return jsonify({"error": "name and host required"}), 400
    targets = _targets()
    key = (name.lower(), host.lower())
    if any((t.get("name", "").lower(), t.get("host", "").lower()) == key for t in targets):
        return jsonify({"error": "target already present"}), 409
    nodes = [n for n in _nodes() if n.get("enabled", True)]
    verification = probe.verify_target({"name": name, "host": host, "country": country}, nodes)
    if not verification["ok"]:
        return jsonify({
            "error": "could not ping target from any node",
            "detail": verification["error"],
            "host": host,
        }), 422
    targets.append({"name": name, "host": verification["host"], "country": country, "source": "admin"})
    _save_targets(targets)
    return jsonify({"message": "added", "verified_from": verification["node"]}), 201


@app.route("/admin/api/targets/<path:name>", methods=["POST"])
def admin_remove_target(name):
    if not _admin_ok():
        return jsonify({"error": "admin access denied"}), 403
    targets = _targets()
    targets = [t for t in targets if t.get("name") != name]
    _save_targets(targets)
    traceroute_mod.remove_target_files(name)
    return jsonify({"message": "removed"})


@app.route("/admin/api/nodes", methods=["GET"])
def admin_list_nodes():
    if not _admin_ok():
        return jsonify({"error": "admin access denied"}), 403
    return jsonify(_nodes())


@app.route("/admin/api/nodes", methods=["POST"])
def admin_add_node():
    if not _admin_ok():
        return jsonify({"error": "admin access denied"}), 403
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    host = (body.get("host") or "").strip()
    if not name or not host:
        return jsonify({"error": "name and host required"}), 400
    nodes = _nodes()
    if any(n.get("name") == name for n in nodes):
        return jsonify({"error": "node already present"}), 409
    node = {
        "name": name,
        "host": host,
        "type": body.get("type", "remote"),
        "ssh_user": body.get("ssh_user"),
        "ssh_port": int(body.get("ssh_port") or 22),
        "enabled": True,
    }
    nodes.append(node)
    _save_nodes(nodes)
    scheduler_mod.scheduler.mark_node_added()
    return jsonify({"message": "added", "backlog": True}), 201


@app.route("/admin/api/nodes/<path:name>", methods=["POST"])
def admin_remove_node(name):
    if not _admin_ok():
        return jsonify({"error": "admin access denied"}), 403
    nodes = [n for n in _nodes() if n.get("name") != name]
    _save_nodes(nodes)
    return jsonify({"message": "removed"})


@app.route("/admin/api/nodes/<path:name>/backlog", methods=["POST"])
def admin_node_backlog(name):
    if not _admin_ok():
        return jsonify({"error": "admin access denied"}), 403
    nodes = _nodes()
    target_node = next((n for n in nodes if n.get("name") == name), None)
    if not target_node:
        return jsonify({"error": "node not found"}), 404
    scheduler_mod.scheduler.mark_node_added()
    return jsonify({"message": "backlog triggered"})


@app.route("/admin/api/verify", methods=["POST"])
def admin_verify():
    if not _admin_ok():
        return jsonify({"error": "admin access denied"}), 403
    body = request.get_json(silent=True) or {}
    host = (body.get("host") or "").strip()
    if not host:
        return jsonify({"error": "host required"}), 400
    nodes = [n for n in _nodes() if n.get("enabled", True)]
    verification = probe.verify_target({"name": host, "host": host}, nodes)
    return jsonify(verification)


@app.route("/admin/api/import", methods=["POST"])
def admin_import():
    if not _admin_ok():
        return jsonify({"error": "admin access denied"}), 403
    nodes = [n for n in _nodes() if n.get("enabled", True)]
    if not nodes:
        return jsonify({"error": "no enabled nodes to verify against"}), 400
    if request.is_json:
        body = request.get_json(silent=True) or {}
        url = body.get("url")
        if not url:
            return jsonify({"error": "url required"}), 400
        try:
            report = import_mod.import_from_url(url, nodes)
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(report)
    # multipart file upload
    if "file" not in request.files:
        return jsonify({"error": "file or url required"}), 400
    f = request.files["file"]
    text = f.read().decode("utf-8", errors="replace")
    report = import_mod.import_text(text, nodes)
    return jsonify(report)


@app.route("/admin/api/summary")
def admin_summary():
    if not _admin_ok():
        return jsonify({"error": "admin access denied"}), 403
    return jsonify(scheduler_mod.scheduler.summary())


application = app

if __name__ == "__main__":
    from waitress import serve
    serve(app, host=BIND_IP, port=BIND_PORT, threads=8)
