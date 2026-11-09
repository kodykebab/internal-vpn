"""Bounded non-root TCP fixture. No files, external endpoints or dependencies."""

import hashlib
import json
import os
import socket
import sys
import time

BLOCK = b"v" * 1024
SIZE = len(BLOCK) * 2048  # 2 MiB per connection, three scenarios only.
EXPECTED = hashlib.sha256(BLOCK * 2048).hexdigest()

if sys.argv[1] == "server":
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((sys.argv[2], 8090))
        listener.listen(1)
        listener.settimeout(30)
        print(json.dumps({"pid": os.getpid(), "ready": True}), flush=True)
        for _ in range(3):
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(10)
                digest, received = hashlib.sha256(), 0
                while True:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > SIZE:
                        raise ValueError("Fixture transfer exceeded bound")
                    digest.update(chunk)
                connection.sendall(
                    json.dumps(
                        {"bytes": received, "valid": received == SIZE and digest.hexdigest() == EXPECTED}
                    ).encode()
                )
else:
    start = time.monotonic()
    with socket.create_connection((sys.argv[2], 8090), timeout=10) as connection:
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for _ in range(2048):
            connection.sendall(BLOCK)
        connection.shutdown(socket.SHUT_WR)
        reply = b""
        while len(reply) < 1024:
            chunk = connection.recv(1024)
            if not chunk:
                break
            reply += chunk
        result = json.loads(reply)
    result["seconds"] = time.monotonic() - start
    result["mbps"] = result["bytes"] * 8 / result["seconds"] / 1_000_000
    print(json.dumps(result))
