from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from common.policy import load_policy


class Handler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path != "/bootstrap":
            self.send_response(404)
            self.end_headers()
            return

        policy = load_policy("policy.json")

        body = json.dumps({
            "epoch_seconds": policy.epoch_seconds,
            "transports": policy.transports,
            "endpoints": policy.endpoints
        }).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    print("Control plane running on :8080")
    server.serve_forever()


if __name__ == "__main__":
    main()
