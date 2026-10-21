"""Exercise the actual linked libcurl against offline, test-only TLS servers."""
import http.server
import os
import pathlib
import ssl
import subprocess
import sys
import tempfile
import threading

normal, denied, fixture_dir, openssl = sys.argv[1:]
temporary = tempfile.TemporaryDirectory(prefix="mailspring-loopback-certificates-")
fixtures = pathlib.Path(temporary.name)
class CRLHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Separate server/log: revocation metadata is never an application
        # credential request, and must not affect credential-leak assertions.
        if self.path == "/healthy.crl":
            data = (fixtures / "healthy.crl").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/pkix-crl")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_error(404)

    def log_message(self, *_):
        pass


crl_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CRLHandler)
generator_environment = dict(os.environ, OPENSSL_EXECUTABLE=openssl)
subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name("generate-loopback-fixtures.py")),
                fixture_dir, str(fixtures), "--crl-url",
                f"http://127.0.0.1:{crl_server.server_port}/healthy.crl"],
               check=True, env=generator_environment)
threading.Thread(target=crl_server.serve_forever, daemon=True).start()
requests = []


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        self.read_and_respond()

    def do_GET(self):
        self.read_and_respond()

    def read_and_respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        requests.append((self.server.kind, self.path, self.headers.get("Authorization"), body))
        redirect = self.server.kind == "redirect" and self.path == "/redirect"
        self.send_response(302 if redirect else 200)
        if redirect:
            self.send_header("Location", f"https://127.0.0.1:{primary.server_port}/redirect-target")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *_):
        pass


def server(kind, certificate=None):
    instance = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    instance.kind = kind
    if certificate:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(fixtures / f"{certificate}.pem", fixtures / f"{certificate}-key.pem")
        instance.socket = context.wrap_socket(instance.socket, server_side=True)
    threading.Thread(target=instance.serve_forever, daemon=True).start()
    return instance


primary = server("primary", "curl-server")
redirect = server("redirect", "curl-redirect")
plaintext = server("plaintext")
revocation_peers = []
if sys.platform == "win32":
    revocation_peers = [server("revoked", "curl-revoked"),
                        server("unavailable-crl", "curl-unavailable")]
environment = {key: value for key, value in os.environ.items()
               if key.lower() not in {"https_proxy", "http_proxy", "all_proxy"}}
ca = str(fixtures / "curl-ca.pem")


def run(client, url, trust, expected, env=environment):
    subprocess.run([client, url, trust, expected], check=True, env=env, timeout=45)


try:
    origin = f"https://127.0.0.1:{primary.server_port}"
    run(normal, origin + "/healthy", ca, "allow")
    assert len(requests) == 2 and all(row[2] == "Bearer local-regression-only" for row in requests)
    before = len(requests)
    run(normal, origin + "/untrusted", "-", "deny")
    run(denied, origin + "/blocked", ca, "deny")
    assert len(requests) == before, "Credentials reached an untrusted or blocked TLS peer"
    run(denied, f"https://127.0.0.1:{redirect.server_port}/redirect", ca, "deny")
    assert len(requests) == before + 1 and requests[-1][0] == "redirect"
    assert not any(row[1] == "/redirect-target" for row in requests), "Redirect bypassed key blocking"
    run(normal, f"https://127.0.0.1:{redirect.server_port}/redirect", ca, "allow")
    run(denied, f"http://127.0.0.1:{plaintext.server_port}/explicit-http", ca, "allow")
    assert sum(row[0] == "plaintext" for row in requests) == 2
    if sys.platform == "win32":
        before = len(requests)
        for peer in revocation_peers:
            run(normal, f"https://127.0.0.1:{peer.server_port}/{peer.kind}", ca, "deny")
        assert len(requests) == before, "Credentials reached a revoked or revocation-unknown peer"
        print("Windows revoked and unavailable-CRL peers rejected before credentials")
    if sys.platform == "darwin":
        for name in ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"]:
            configured = dict(environment, **{name: "hTtPs://unused.invalid:443"})
            run(normal, origin, ca, "configure-denied", configured)
    print("Healthy/reused HTTPS, untrusted and blocked peers, redirects and explicit HTTP passed")
finally:
    for instance in [primary, redirect, plaintext, crl_server, *revocation_peers]:
        instance.shutdown()
        instance.server_close()
    temporary.cleanup()
