#!/usr/bin/env python3
# register_server.py - demo: 启动临时 HTTP server 并向 coordinator 注册端口
import http.server
import socketserver
import threading
import json
import socket
import sys
import os

COORDINATOR_SOCKET = '/tmp/agentbox_port.sock'

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'hello from agent')


def register_port(port):
    if not os.path.exists(COORDINATOR_SOCKET):
        print('coordinator socket not found, skipping registration')
        return
    payload = {"action":"register","port":port,"proto":"tcp","purpose":"http-api"}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(COORDINATOR_SOCKET)
        s.sendall((json.dumps(payload) + "\n").encode())
        data = s.recv(4096)
        print('coordinator response:', data.decode())


def run_server():
    with socketserver.TCPServer(("", 0), Handler) as httpd:
        port = httpd.server_address[1]
        print('server started on port', port)
        register_port(port)
        httpd.serve_forever()

if __name__ == '__main__':
    run_server()
