#!/usr/bin/env python3
"""
Simple Secret Broker HTTP demo.
POST /create -> returns JSON {"path":"/tmp/agent_secret_xxx"}
POST /delete -> accepts JSON {"path":"..."} and deletes the file
"""
import http.server
import socketserver
import json
import os
import tempfile

PORT = 12700

class Handler(http.server.BaseHTTPRequestHandler):
    def _send_json(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length)
        try:
            obj = json.loads(body.decode()) if body else {}
        except Exception:
            obj = {}
        if self.path == '/create':
            fd, path = tempfile.mkstemp(prefix='agent_secret_')
            os.write(fd, b'SECRET=demo\n')
            os.close(fd)
            os.chmod(path, 0o600)
            self._send_json({'path': path})
        elif self.path == '/delete':
            p = obj.get('path')
            if p and os.path.exists(p):
                os.remove(p)
                self._send_json({'status': 'deleted'})
            else:
                self._send_json({'status': 'not_found'}, status=404)
        else:
            self._send_json({'error': 'unknown'}, status=404)


def main():
    with socketserver.TCPServer(('127.0.0.1', PORT), Handler) as httpd:
        print('secret broker listening on', PORT)
        httpd.serve_forever()

if __name__ == '__main__':
    main()
