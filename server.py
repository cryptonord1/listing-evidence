import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import html
import secrets
import threading
import time
from urllib.parse import parse_qs, urlsplit
import agent

GATE = threading.BoundedSemaphore(8)
RATE_LOCK = threading.Lock()
WINDOW = {'at': time.monotonic(), 'requests': 0}
SETUP_LOCK = threading.Lock()


def setup_valid(token):
    try:
        state = json.loads((agent.PRIVATE / 'setup-capability.json').read_text())
        return not state.get('used') and time.time() < state['expires_at'] and hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), state['sha256'])
    except (FileNotFoundError, ValueError, KeyError, TypeError):
        return False


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body, content_type='application/json', sign=False, download=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, separators=(',', ':'), ensure_ascii=True).encode()
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        if download:
            self.send_header('Content-Disposition', 'attachment; filename="'+download+'"')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if sign and agent.platform_secret():
            digest = hmac.new(agent.platform_secret().encode(), body, hashlib.sha256).hexdigest()
            self.send_header('x-agent-games-signature', digest)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        route = urlsplit(self.path)
        if route.path == '/health':
            self.reply(200, {'ok': True, 'agent': 'Listing Evidence', 'track': 'wildcard', 'platform_secret_configured': bool(agent.platform_secret())})
        elif route.path == '/setup':
            token = parse_qs(route.query).get('key', [''])[0]
            if not setup_valid(token):
                self.reply(403, {'error': 'Setup link is invalid, expired or already used'})
                return
            content = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Connect Listing Evidence</title><link rel="stylesheet" href="/style.css"><main><h1>Connect the agent.</h1><p>Paste only the Agent Games HMAC secret issued for Listing Evidence by the dashboard’s Rotate Secret action. This form configures the research service; it does not sign into your account.</p><p>Do not enter a password, login code, wallet seed or private key.</p><form action="/setup" method="post"><input type="hidden" name="key" value="'+html.escape(token, quote=True)+'"><label>Agent Games HMAC secret<input type="password" name="secret" required minlength="32" maxlength="256" autocomplete="off"></label><button>Save service secret</button></form><p>The link expires and works once. The secret is stored privately and never shown on the public demo.</p></main></html>'
            self.reply(200, content, 'text/html; charset=utf-8')
        elif route.path in ['/', '/app.js', '/style.css']:
            name = {'/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css'}[route.path]
            content_type = {'/': 'text/html; charset=utf-8', '/app.js': 'text/javascript; charset=utf-8', '/style.css': 'text/css; charset=utf-8'}[route.path]
            path = agent.ROOT / 'public' / name
            if not path.is_file():
                path = agent.ROOT / name
            self.reply(200, path.read_bytes(), content_type)
        elif route.path == '/download/server.py':
            self.reply(200, (agent.ROOT / 'server.py').read_bytes(), 'text/plain; charset=utf-8', download='server.py')
        elif route.path == '/about':
            self.reply(200, (agent.ROOT / 'PUBLIC.md').read_text(), 'text/plain; charset=utf-8')
        elif route.path == '/entry':
            self.reply(200, (agent.ROOT / 'ENTRY.txt').read_text(), 'text/plain; charset=utf-8')
        elif route.path == '/source.zip':
            self.reply(200, (agent.ROOT / 'public' / 'listing-evidence-source.zip').read_bytes(), 'application/zip')
        elif route.path == '/api/report':
            with RATE_LOCK:
                if time.monotonic() - WINDOW['at'] > 60:
                    WINDOW.update(at=time.monotonic(), requests=0)
                WINDOW['requests'] += 1
                limited = WINDOW['requests'] > 60
            if limited or not GATE.acquire(blocking=False):
                self.reply(429, {'error': 'Demo is busy. Please try again in a minute.'})
                return
            try:
                query = {k: v[0] for k, v in parse_qs(route.query).items()}
                agent.normalize(query)
                self.reply(200, agent.run(query))
            except ValueError as exc:
                self.reply(400, {'error': str(exc)})
            except Exception:
                self.reply(503, {'error': 'Research is temporarily unavailable'})
            finally:
                GATE.release()
        elif route.path.startswith('/evidence/'):
            sha = route.path[len('/evidence/'):]
            if not agent.re.fullmatch('[0-9a-f]{64}', sha):
                self.reply(404, {'error': 'Snapshot not found'})
                return
            with agent.connect() as db:
                row = db.execute('SELECT body FROM sources WHERE sha=?', (sha,)).fetchone()
            self.reply(200 if row else 404, row[0] if row else {'error': 'Snapshot not found'})
        else:
            self.reply(404, {'error': 'Not found'})

    def do_POST(self):
        if urlsplit(self.path).path == '/setup':
            try:
                self.connection.settimeout(10)
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 2048:
                    raise ValueError('Invalid setup request')
                form = parse_qs(self.rfile.read(size).decode())
                token = form.get('key', [''])[0]
                secret = form.get('secret', [''])[0].strip()
                with SETUP_LOCK:
                    if not setup_valid(token):
                        self.reply(403, {'error': 'Setup link is invalid, expired or already used'})
                        return
                    if not 32 <= len(secret) <= 256 or not agent.re.fullmatch('[A-Za-z0-9_+/=.-]+', secret):
                        raise ValueError('Check that you copied the complete HMAC service secret')
                    path = agent.PRIVATE / 'platform-secret.json'
                    tmp = agent.PRIVATE / ('secret-'+secrets.token_hex(8)+'.tmp')
                    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    with os.fdopen(fd, 'w') as target:
                        json.dump({'secret':secret,'configured_at':agent.utc()}, target)
                    os.replace(tmp, path)
                    state_path = agent.PRIVATE / 'setup-capability.json'
                    state = json.loads(state_path.read_text());state['used'] = True;state_path.write_text(json.dumps(state))
                self.reply(200, '<!doctype html><html lang="en"><meta charset="utf-8"><title>Agent connected</title><link rel="stylesheet" href="/style.css"><main><h1>Service secret saved.</h1><p>Now return to Agent Games and run the agent preflight. This has configured the service, but has not submitted a competition entry.</p></main></html>', 'text/html; charset=utf-8')
            except (ValueError, UnicodeDecodeError):
                self.reply(400, {'error':'Check the setup form and try again. No secret is shown in this response.'})
            except Exception:
                self.reply(503, {'error':'Setup could not be completed'})
            return
        if urlsplit(self.path).path != '/agent':
            self.reply(404, {'error': 'Not found'})
            return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 16384:
                raise ValueError('Invalid request size')
            self.connection.settimeout(10)
            raw = self.rfile.read(size)
            secret = agent.platform_secret()
            result = agent.signed_task(raw, self.headers.get('x-agent-games-signature', ''), secret)
            if result == {'ok': True, 'protocolVersion': 'v1'}:
                (agent.PRIVATE / 'preflight-received.json').write_text(json.dumps({'received_at':agent.utc(),'signature_verified':True,'response_signed':True}))
            self.reply(200, result, sign=True)
        except PermissionError as exc:
            self.reply(401, {'error': str(exc)})
        except (ValueError, json.JSONDecodeError) as exc:
            self.reply(400, {'error': str(exc)}, sign=True)
        except Exception:
            self.reply(503, {'error': 'Task could not be completed'}, sign=True)


if __name__ == '__main__':
    os.umask(0o077)
    ThreadingHTTPServer(('127.0.0.1', int(os.environ.get('PORT', '8768'))), Handler).serve_forever()
