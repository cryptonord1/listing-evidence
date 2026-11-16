import hashlib
import hmac
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest.mock import patch
import agent
import server


class SetupTests(unittest.TestCase):
    def test_single_use_setup_and_signed_preflight(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(agent, 'PRIVATE', Path(tmp)), patch.dict(agent.os.environ, {'AGENT_GAMES_HMAC_SECRET': ''}):
            token = 'a' * 64
            path = Path(tmp) / 'setup-capability.json'
            path.write_text(json.dumps({'sha256': hashlib.sha256(token.encode()).hexdigest(), 'expires_at': time.time()+60, 'used': False}))
            service = ThreadingHTTPServer(('127.0.0.1',0), server.Handler)
            thread = threading.Thread(target=service.serve_forever, daemon=True);thread.start()
            base = 'http://127.0.0.1:'+str(service.server_port)
            try:
                with self.assertRaises(urllib.error.HTTPError) as failed:
                    urllib.request.urlopen(base+'/setup?key=wrong')
                self.assertEqual(failed.exception.code,403)
                html = urllib.request.urlopen(base+'/setup?key='+token).read()
                self.assertIn(b'type="password"',html)
                secret = 's' * 64
                data = urllib.parse.urlencode({'key':token,'secret':secret}).encode()
                response = urllib.request.urlopen(urllib.request.Request(base+'/setup',data=data))
                self.assertNotIn(secret.encode(),response.read())
                self.assertEqual(agent.platform_secret(),secret)
                self.assertEqual((Path(tmp)/'platform-secret.json').stat().st_mode & 0o777,0o600)
                with self.assertRaises(urllib.error.HTTPError) as replay:
                    urllib.request.urlopen(urllib.request.Request(base+'/setup',data=data))
                self.assertEqual(replay.exception.code,403)
                raw = json.dumps({'type':'agent-games.preflight.v1','issued_at':agent.utc()}).encode()
                sig = hmac.new(secret.encode(),raw,hashlib.sha256).hexdigest()
                request = urllib.request.Request(base+'/agent',data=raw,headers={'x-agent-games-signature':sig,'Content-Type':'application/json'})
                response = urllib.request.urlopen(request);body = response.read()
                self.assertEqual(json.loads(body),{'ok':True,'protocolVersion':'v1'})
                self.assertEqual(response.headers['x-agent-games-signature'],hmac.new(secret.encode(),body,hashlib.sha256).hexdigest())
            finally:
                service.shutdown();service.server_close();thread.join()


if __name__ == '__main__':unittest.main()
