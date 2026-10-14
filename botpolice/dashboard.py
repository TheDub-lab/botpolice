"""Optional read-only dashboard (requires Flask).

A tiny local viewer for the event log. It only ever reads; there are no routes
that mutate state or make outbound requests. It binds to the configured bind
address (loopback by default) and is disabled unless ``dashboard.enabled`` is
true. If Flask is not installed the listener keeps running without it.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from .config import Config
from .eventlog import verify_log


def _read_events(path: Path, limit: int) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as fh:
        lines = fh.readlines()
    events: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    events.reverse()
    return events


def create_app(config: Config):
    from flask import Flask, jsonify, request

    app = Flask(__name__)
    log_path = config.resolve(config.log_path)

    @app.get("/")
    def index():
        return _PAGE

    @app.get("/api/events")
    def events():
        limit = min(int(request.args.get("limit", 200)), 5000)
        return jsonify(_read_events(log_path, limit))

    @app.get("/api/verify")
    def verify():
        return jsonify(verify_log(log_path).to_dict())

    return app


_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>botpolice</title>
<style>body{font-family:monospace;background:#111;color:#ddd;margin:2rem}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #333;padding:4px 8px;font-size:12px}
.high{color:#f66}.medium{color:#fc6}.info{color:#6cf}</style></head>
<body><h1>botpolice events</h1>
<p id="verify"></p>
<table id="t"><thead><tr><th>time</th><th>sev</th><th>event</th><th>service</th>
<th>src</th><th>placement</th><th>summary</th></tr></thead><tbody></tbody></table>
<script>
fetch('/api/verify').then(r=>r.json()).then(v=>{document.getElementById('verify').textContent=
 v.ok?`chain OK (${v.entries} entries)`:`CHAIN BROKEN at line ${v.first_broken_line}: ${v.reason}`});
fetch('/api/events?limit=200').then(r=>r.json()).then(rows=>{
 const tb=document.querySelector('#t tbody');
 for(const e of rows){const tr=document.createElement('tr');
  const cells=[e.ts,e.severity,e.event,e.service,(e.src_ip||'')+':'+(e.src_port||''),e.placement||'',e.summary||''];
  for(const c of cells){const td=document.createElement('td');td.textContent=c==null?'':c;tr.appendChild(td);}
  tr.className=e.severity||'';tb.appendChild(tr);}});
</script></body></html>
"""


class DashboardServer:
    def __init__(self, httpd) -> None:
        self._httpd = httpd
        self._thread = threading.Thread(target=httpd.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def shutdown(self) -> None:
        try:
            self._httpd.shutdown()
            self._thread.join(timeout=5)
        except Exception:
            pass


def start_dashboard(config: Config) -> DashboardServer | None:
    """Start the dashboard thread, or return None (disabled / Flask missing)."""
    if not config.dashboard.enabled:
        return None
    try:
        from werkzeug.serving import make_server
    except ImportError:
        print("botpolice: dashboard requested but Flask/Werkzeug is not installed; skipping")
        return None

    app = create_app(config)
    httpd = make_server(config.bind, config.dashboard.port, app, threaded=True)
    server = DashboardServer(httpd)
    server.start()
    print(f"botpolice: dashboard on http://{config.bind}:{config.dashboard.port}", flush=True)
    return server
