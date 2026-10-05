"""Local-only web UI. Stdlib http.server only.

No route ever returns a secret value. store.py's value-reading functions
(_resolve, _resolve_group) are never imported here.
"""
import json
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote, urlparse

from . import store

MASK = "•" * 8


def _group_view(group):
    return {
        "name": group,
        "keys": [
            {"key": k, "ref": store.ref(group, k), "value": MASK}
            for k in store.list_keys(group)
        ],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "sealref/1"

    def log_message(self, fmt, *args):
        pass  # Known limit: silence default access log, personal tool

    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body_json(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw or b"{}")

    def _allowed(self):
        """Reject DNS-rebinding (bad Host) and cross-site requests (bad Origin,
        non-JSON bodies). Everything here is local-only, so be strict."""
        port = self.server.server_port
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if self.headers.get("Host") not in hosts:
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin not in {f"http://{h}" for h in hosts}:
            return False
        if self.command in ("POST", "DELETE") and self.headers.get("X-Vaultlet") != "1":
            return False  # custom header forces a CORS preflight, which we never grant
        return True

    def do_GET(self):
        if not self._allowed():
            return self._json(403, {"error": "forbidden"})
        path = urlparse(self.path).path
        if path == "/":
            self._html(PAGE)
        elif path == "/api/groups":
            self._json(200, [_group_view(g) for g in store.list_groups()])
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._allowed():
            return self._json(403, {"error": "forbidden"})
        path = urlparse(self.path).path
        if path == "/api/quit":
            self._json(200, {"ok": True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        try:
            body = self._body_json()
            if path == "/api/groups":
                store.create_group(body["group"])
                self._json(200, {"ok": True})
            elif path == "/api/keys":
                store.set_secret(body["group"], body["key"], body["value"])
                self._json(200, {"ok": True})
            else:
                self._json(404, {"error": "not found"})
        except (ValueError, KeyError, TypeError) as e:
            self._json(400, {"error": str(e)})
        except RuntimeError as e:
            self._json(500, {"error": str(e)})

    def do_DELETE(self):
        if not self._allowed():
            return self._json(403, {"error": "forbidden"})
        parts = [unquote(p) for p in urlparse(self.path).path.strip("/").split("/")]
        try:
            if parts[:1] == ["api"] and parts[1:2] == ["groups"] and len(parts) == 3:
                store.delete_group(parts[2])
                self._json(200, {"ok": True})
            elif parts[:1] == ["api"] and parts[1:2] == ["keys"] and len(parts) == 4:
                store.delete(parts[2], parts[3])
                self._json(200, {"ok": True})
            else:
                self._json(404, {"error": "not found"})
        except ValueError as e:
            self._json(400, {"error": str(e)})


def _make_server(port):
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(port=8765):
    server = _make_server(port)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"sealref: serving on {url}")
    webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


def serve_until(group, key, reason, timeout=300):
    store._validate_key(key)
    if group not in store.list_groups():
        store.create_group(group)  # raises ValueError on a bad name, propagates
    server = _make_server(0)
    q = f"?group={quote(group)}&key={quote(key)}"
    if reason:
        q += f"&reason={quote(reason)}"
    url = f"http://127.0.0.1:{server.server_port}/{q}"
    print(f"sealref: serving on {url}")
    webbrowser.open(url)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
    thread.start()
    deadline = time.time() + timeout
    found = False
    while time.time() < deadline:
        if store.has(group, key):
            found = True
            break
        time.sleep(0.3)
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
    return found


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sealref</title>
<style>
  :root {
    --bg: #f7f7f5; --panel: #fff; --text: #1c1c1c; --muted: #6b6b6b;
    --border: #e2e2e0; --accent: #2f6f4f; --danger: #b3382c; --mono: ui-monospace, Menlo, monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #17181a; --panel: #1f2023; --text: #eaeaea; --muted: #9a9a9a;
      --border: #303236; --accent: #5fb98a; --danger: #e0685c; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  main { max-width: 640px; margin: 0 auto; padding: 40px 20px 80px; }
  h1 { font-size: 20px; font-weight: 600; margin: 0 0 4px; }
  .sub { color: var(--muted); font-size: 13px; margin-bottom: 28px; }
  .banner { background: #fff4e0; border: 1px solid #e0b25a; color: #6b4a10;
    border-radius: 8px; padding: 12px 14px; margin-bottom: 20px; font-size: 14px; }
  @media (prefers-color-scheme: dark) {
    .banner { background: #3a2f14; border-color: #7a5a1e; color: #f0cf8a; }
  }
  .toast { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
    padding: 10px 18px; border-radius: 8px; font-size: 14px; opacity: 0; transition: opacity .2s;
    background: var(--accent); color: #fff; pointer-events: none; }
  .toast.err { background: var(--danger); }
  .toast.show { opacity: 1; }
  .group { background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    margin-bottom: 16px; overflow: hidden; }
  .group.requested { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
  .group-head { display: flex; align-items: center; justify-content: space-between;
    padding: 12px 16px; border-bottom: 1px solid var(--border); }
  .group-head h2 { font-size: 15px; margin: 0; font-family: var(--mono); }
  .key-row { display: flex; align-items: center; gap: 10px; padding: 10px 16px;
    border-bottom: 1px solid var(--border); }
  .key-row:last-child { border-bottom: none; }
  .key-row .name { font-family: var(--mono); font-size: 13px; min-width: 120px; }
  .key-row .mask { color: var(--muted); font-family: var(--mono); flex: 1; }
  button { font: inherit; cursor: pointer; border: 1px solid var(--border); background: var(--panel);
    color: var(--text); border-radius: 6px; padding: 6px 10px; font-size: 13px; }
  button:hover { border-color: var(--accent); }
  button.danger:hover { border-color: var(--danger); color: var(--danger); }
  button.primary { background: var(--accent); color: #fff; border-color: var(--accent); }
  .empty { color: var(--muted); text-align: center; padding: 40px 0; border: 1px dashed var(--border);
    border-radius: 10px; }
  .add-key { display: flex; gap: 6px; padding: 12px 16px; flex-wrap: wrap; }
  .add-key input { flex: 1; min-width: 100px; }
  input[type=text], input[type=password] { font: inherit; padding: 7px 9px; border-radius: 6px;
    border: 1px solid var(--border); background: var(--bg); color: var(--text); }
  .new-group { display: flex; gap: 8px; margin-bottom: 24px; }
  .new-group input { flex: 1; }
  .pw-wrap { display: flex; gap: 4px; align-items: center; flex: 1; min-width: 140px; }
</style>
</head>
<body>
<main>
  <h1>sealref</h1>
  <div class="sub">Values go to the macOS Keychain from this page — never into the agent chat.</div>
  <div id="banner"></div>
  <div class="new-group">
    <input id="new-group-name" type="text" placeholder="new group name">
    <button class="primary" id="new-group-btn">Create group</button>
  </div>
  <div id="groups"></div>
</main>
<div class="toast" id="toast"></div>
<script>
const params = new URLSearchParams(location.search);
const focusGroup = params.get('group');
const focusKey = params.get('key');
const reason = params.get('reason');

if (reason) {
  document.getElementById('banner').innerHTML =
    '<div class="banner">Claude needs a secret: ' + escapeHtml(reason) + '</div>';
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function toast(msg, isErr) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show' + (isErr ? ' err' : '');
  setTimeout(() => t.className = 'toast', 1800);
}

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? {'Content-Type': 'application/json', 'X-Vaultlet': '1'} : {'X-Vaultlet': '1'},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

async function load() {
  const groups = await api('GET', '/api/groups');
  render(groups);
}

function render(groups) {
  const el = document.getElementById('groups');
  el.innerHTML = '';
  // Requested group may not exist as a real group yet (e.g. request_secret for
  // a brand-new group) - show its card anyway so there's always a place to fill it in.
  if (focusGroup && !groups.some(g => g.name === focusGroup)) {
    groups = [{name: focusGroup, keys: []}, ...groups];
  }
  if (!groups.length) {
    el.innerHTML = '<div class="empty">No groups yet. Create one above to get started.</div>';
    return;
  }
  for (const g of groups) {
    el.appendChild(renderGroup(g));
  }
  if (focusGroup && focusKey) {
    const input = [...document.querySelectorAll('input[data-focus]')]
      .find(i => i.dataset.focus === focusGroup + '/' + focusKey);
    if (input) { input.focus(); input.scrollIntoView({block: 'center'}); }
  }
}

function renderGroup(g) {
  const wrap = document.createElement('div');
  wrap.className = 'group' + (g.name === focusGroup ? ' requested' : '');

  const head = document.createElement('div');
  head.className = 'group-head';
  head.innerHTML = `<h2>${escapeHtml(g.name)}</h2>`;
  const delGroupBtn = document.createElement('button');
  delGroupBtn.className = 'danger';
  delGroupBtn.textContent = 'Delete group';
  delGroupBtn.onclick = async () => {
    if (!confirm(`Delete group "${g.name}" and all its secrets?`)) return;
    try { await api('DELETE', `/api/groups/${encodeURIComponent(g.name)}`); toast('Group deleted'); load(); }
    catch (e) { toast(e.message, true); }
  };
  head.appendChild(delGroupBtn);
  wrap.appendChild(head);

  for (const k of g.keys) {
    const row = document.createElement('div');
    row.className = 'key-row';
    row.innerHTML = `<span class="name">${escapeHtml(k.key)}</span><span class="mask">${k.value}</span>`;
    const copyBtn = document.createElement('button');
    copyBtn.textContent = 'Copy ref';
    copyBtn.onclick = () => { navigator.clipboard.writeText(k.ref); toast('Ref copied'); };
    const delBtn = document.createElement('button');
    delBtn.className = 'danger';
    delBtn.textContent = 'Delete';
    delBtn.onclick = async () => {
      try { await api('DELETE', `/api/keys/${encodeURIComponent(g.name)}/${encodeURIComponent(k.key)}`); toast('Key deleted'); load(); }
      catch (e) { toast(e.message, true); }
    };
    row.appendChild(copyBtn);
    row.appendChild(delBtn);
    wrap.appendChild(row);
  }

  const addRow = document.createElement('div');
  addRow.className = 'add-key';
  const isFocus = g.name === focusGroup;
  addRow.innerHTML = `
    <input type="text" placeholder="key name" class="key-input" value="${isFocus && focusKey ? escapeHtml(focusKey) : ''}">
    <span class="pw-wrap">
      <input type="password" placeholder="value" class="val-input" ${isFocus ? `data-focus="${escapeHtml(g.name + '/' + focusKey)}"` : ''}>
      <button type="button" class="show-btn">show</button>
    </span>
    <button class="primary add-btn">Save</button>
  `;
  const keyInput = addRow.querySelector('.key-input');
  const valInput = addRow.querySelector('.val-input');
  addRow.querySelector('.show-btn').onclick = (e) => {
    valInput.type = valInput.type === 'password' ? 'text' : 'password';
    e.target.textContent = valInput.type === 'password' ? 'show' : 'hide';
  };
  addRow.querySelector('.add-btn').onclick = async () => {
    const key = keyInput.value.trim();
    const value = valInput.value;
    if (!key || !value) { toast('Key and value are required', true); return; }
    try {
      await api('POST', '/api/keys', {group: g.name, key, value});
      toast('Saved');
      load();
    } catch (e) { toast(e.message, true); }
  };
  wrap.appendChild(addRow);

  return wrap;
}

document.getElementById('new-group-btn').onclick = async () => {
  const input = document.getElementById('new-group-name');
  const name = input.value.trim();
  if (!name) return;
  try {
    await api('POST', '/api/groups', {group: name});
    input.value = '';
    toast('Group created');
    load();
  } catch (e) { toast(e.message, true); }
};

load();
</script>
</body>
</html>
"""
