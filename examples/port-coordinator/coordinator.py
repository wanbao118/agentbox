#!/usr/bin/env python3
import socket
import os
import json
import argparse

SOCK_PATH = '/tmp/agentbox_port.sock'


def handle_client(conn):
    buf = b''
    while True:
        data = conn.recv(4096)
        if not data:
            break
        buf += data
        if b'\n' in buf:
            line, buf = buf.split(b'\n', 1)
            try:
                obj = json.loads(line.decode())
                print('register request:', obj)
                # here we would update proxy configuration; for demo reply with proxy endpoint
                resp = {"status": "ok", "proxy_endpoint": "127.0.0.1:16000"}
            except Exception as e:
                resp = {"status": "error", "error": str(e)}
            conn.sendall((json.dumps(resp) + "\n").encode())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--socket', default=SOCK_PATH)
    args = parser.parse_args()
    path = args.socket
    if os.path.exists(path):
        os.remove(path)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.bind(path)
        s.listen()
        print('coordinator listening on', path)
        while True:
            conn, _ = s.accept()
            with conn:
                handle_client(conn)

if __name__ == '__main__':
    main()
