"""Transport: a multi-process HTTP/1.1 deployment on localhost (used for all measurements) and an
in-process transport (used for unit tests). Both serialize every message to JSON bytes.
"""
import http.client
import os
import socket
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import services as S


class CallTimeout(Exception):
    def __init__(self, service, cid=None):
        super().__init__("timeout calling %s" % service)
        self.service, self.cid = service, cid


class CallError(Exception):
    def __init__(self, service, status, body, cid=None):
        super().__init__("HTTP %s from %s: %s" % (status, service, body[:120]))
        self.service, self.status, self.body, self.cid = service, status, body, cid


# ------------------------------------------------------------------------------ server

def serve(port, names):
    catalog = S.build_catalog()
    hosted = set(names)

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def setup(self):
            super().setup()
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(n) if n else b""
            _, svc, op = self.path.split("/", 2)
            if svc not in hosted:
                status, out, sleep = 404, b'{"error":"no such service"}', 0.0
            else:
                status, out, sleep = S.handle(catalog, svc, op, raw, self.headers)
            if sleep:
                time.sleep(sleep)
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)
            except (BrokenPipeError, ConnectionResetError):
                pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.daemon_threads = True
    srv.serve_forever()


# ------------------------------------------------------------------------------ clients

class HttpClient:
    def __init__(self, endpoints):
        self.endpoints = endpoints  # service -> port
        self.conns = {}

    def _conn(self, port):
        c = self.conns.get(port)
        if c is None:
            c = http.client.HTTPConnection("127.0.0.1", port)
            self.conns[port] = c
        return c

    def _drop(self, port):
        c = self.conns.pop(port, None)
        if c is not None:
            c.close()

    def call(self, service, op, data, headers, timeout_s):
        port = self.endpoints[service]
        c = self._conn(port)
        h = {"Content-Type": "application/json", "Content-Length": str(len(data))}
        h.update(headers)
        try:
            if c.sock is None:
                c.connect()
                c.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            c.sock.settimeout(timeout_s)
            c.request("POST", "/%s/%s" % (service, op), body=data, headers=h)
            r = c.getresponse()
            body = r.read()
            return r.status, body
        except (socket.timeout, TimeoutError):
            self._drop(port)
            raise CallTimeout(service)
        except (ConnectionError, http.client.HTTPException, OSError):
            self._drop(port)
            # one reconnect attempt for stale keep-alive connections
            c = self._conn(port)
            c.connect()
            c.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            c.sock.settimeout(timeout_s)
            try:
                c.request("POST", "/%s/%s" % (service, op), body=data, headers=h)
                r = c.getresponse()
                return r.status, r.read()
            except (socket.timeout, TimeoutError):
                self._drop(port)
                raise CallTimeout(service)


class InProcClient:
    """Same serialization and fault semantics, no network (unit tests)."""

    def __init__(self):
        self.catalog = S.build_catalog()

    def call(self, service, op, data, headers, timeout_s):
        status, out, sleep = S.handle(self.catalog, service, op, data, headers)
        if sleep and sleep >= timeout_s:
            raise CallTimeout(service)
        return status, out


# ------------------------------------------------------------------------------ cluster

class Cluster:
    def __init__(self, base_port=18100):
        self.procs = []
        self.endpoints = {}
        port = base_port
        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + os.pathsep + env.get("PYTHONPATH", "")
        for _, names in S.PROCESS_GROUPS.items():
            p = subprocess.Popen([sys.executable, "-m", "aina.transport", str(port), ",".join(names)], env=env)
            self.procs.append(p)
            for n in names:
                self.endpoints[n] = port
            port += 1
        self._wait()

    def _wait(self):
        cl = HttpClient(self.endpoints)
        for svc in set(self.endpoints):
            for _ in range(200):
                try:
                    cl.call(svc, "ping", b"", {}, 1.0)
                    break
                except Exception:
                    time.sleep(0.05)
            else:
                raise RuntimeError("service %s did not start" % svc)

    def client(self):
        return HttpClient(self.endpoints)

    def close(self):
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            p.wait(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


if __name__ == "__main__":
    serve(int(sys.argv[1]), sys.argv[2].split(","))
