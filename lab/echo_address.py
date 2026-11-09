"""Non-root HTTP fixture for verifying routed source addresses."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"source": self.client_address[0]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


HTTPServer((sys.argv[1], 8089), Handler).serve_forever()
