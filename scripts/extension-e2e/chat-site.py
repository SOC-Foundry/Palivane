#!/usr/bin/env python3
"""A stand-in for claude.ai / chatgpt.com for the extension harness (e2e.mjs).

HTTPS (--https-port) serves a one-box "chat page" that sends its prompt the way the real sites
do (and in the other shapes a page may use: Request object, Blob, bytes, stream, XHR) and
records whatever ARRIVES, which is what a block is supposed to stop. A plain-HTTP control port
(--ctl-port) lets the test read and clear that log: GET /__log, DELETE /__log."""
import argparse, json, ssl, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = []
PAGE = """<!doctype html><meta charset=utf-8><title>%(host)s</title>
<textarea id=prompt rows=3 cols=60></textarea><button id=send>Send</button><pre id=out></pre>
<script>
const host = location.hostname;
const mode = new URLSearchParams(location.search).get('mode') || 'string';
document.getElementById('send').onclick = async () => {
  const text = document.getElementById('prompt').value;
  let h = {'content-type': 'application/json'};
  let url, body;
  if (host === 'gemini.google.com') {
    // Gemini sends a form-encoded body, not JSON: the extension scans the raw text.
    url = '/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate';
    body = new URLSearchParams({'f.req': JSON.stringify([null, JSON.stringify([[text]])])});
  } else if (host === 'chatgpt.com') {
    url = '/backend-api/f/conversation';
    body = JSON.stringify({action: 'next', messages: [{id: 'm1', author: {role: 'user'}, content: {content_type: 'text', parts: [text]}}]});
  } else {
    url = '/api/organizations/o1/chat_conversations/c1/completion';
    body = JSON.stringify({prompt: text, timezone: 'UTC', attachments: [], files: []});
  }
  if (body instanceof URLSearchParams) h = {};
  const out = (t) => { document.getElementById('out').textContent = t; };
  try {
    let r;
    if (mode === 'request') r = await fetch(new Request(url, {method: 'POST', headers: h, body}));
    else if (mode === 'blob') r = await fetch(url, {method: 'POST', headers: h, body: new Blob([body], {type: 'application/json'})});
    else if (mode === 'bytes') r = await fetch(url, {method: 'POST', headers: h, body: new TextEncoder().encode(body)});
    else if (mode === 'stream') r = await fetch(url, {method: 'POST', headers: h, duplex: 'half',
      body: new ReadableStream({start(c) { c.enqueue(new TextEncoder().encode(body)); c.close(); }})});
    else if (mode === 'xhr' || mode === 'xhrblob') {
      r = await new Promise((resolve) => { const x = new XMLHttpRequest(); x.open('POST', url); x.setRequestHeader('content-type', 'application/json');
        x.onloadend = () => resolve({status: x.status}); x.send(mode === 'xhr' ? body : new Blob([body], {type: 'application/json'})); });
    } else r = await fetch(url, {method: 'POST', headers: h, body});
    out('status ' + r.status);
  } catch (e) { out('network error ' + e); }
};
</script>"""


class Site(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        host = (self.headers.get('Host') or '').split(':')[0]
        b = (PAGE % {'host': host}).encode()
        self.send_response(200); self.send_header('content-type', 'text/html'); self.send_header('content-length', str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_POST(self):
        n = int(self.headers.get('content-length') or 0)
        body = self.rfile.read(n).decode('utf8', 'replace') if n else ''
        LOG.append({'host': (self.headers.get('Host') or '').split(':')[0], 'path': self.path, 'body': body[:400], 'at': time.time()})
        b = b'{"ok":true}'
        self.send_response(200); self.send_header('content-type', 'application/json'); self.send_header('content-length', str(len(b))); self.end_headers(); self.wfile.write(b)


class Ctl(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        b = json.dumps(LOG).encode(); self.send_response(200); self.send_header('content-length', str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_DELETE(self):
        LOG.clear(); self.send_response(204); self.end_headers()


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--https-port', type=int, required=True); ap.add_argument('--ctl-port', type=int, required=True)
    ap.add_argument('--cert', required=True); ap.add_argument('--key', required=True)
    a = ap.parse_args()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(a.cert, a.key)
    https = ThreadingHTTPServer(('127.0.0.1', a.https_port), Site); https.socket = ctx.wrap_socket(https.socket, server_side=True)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    ThreadingHTTPServer(('127.0.0.1', a.ctl_port), Ctl).serve_forever()
