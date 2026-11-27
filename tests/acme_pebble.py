#!/usr/bin/env python3
"""Exercise Rocky's HTTP-01 certificate lifecycle with a local Pebble issuer."""

import argparse
import contextlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time


HOST = "rocky.test"
CHALLENGE_PREFIX = "/.well-known/acme-challenge/"


def available_ports(count):
    with contextlib.ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(count)]
        for listener in sockets:
            listener.bind(("127.0.0.1", 0))
        return [listener.getsockname()[1] for listener in sockets]


def wait_until(description, predicate, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = predicate()
        except (OSError, subprocess.CalledProcessError):
            result = None
        if result:
            return result
        time.sleep(0.05)
    raise RuntimeError(f"Timed out waiting for {description}")


def serve_dns(listener):
    # Pebble looks up the fixture hostname over TCP. The fixture has one IPv4 address.
    while True:
        try:
            connection, _ = listener.accept()
        except OSError:
            return
        with connection, connection.makefile("rb") as source:
            query = source.read(int.from_bytes(source.read(2), "big"))
            end = 12
            labels = []
            while query[end]:
                length = query[end]
                labels.append(query[end + 1 : end + 1 + length])
                end += length + 1
            question = query[12 : end + 5]
            ipv4 = b".".join(labels) == HOST.encode() and query[end + 1 : end + 3] == b"\x00\x01"
            counts = bytes([0, 1, 0, int(ipv4), 0, 0, 0, 0])
            answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x7f\x00\x00\x01" if ipv4 else b""
            response = query[:2] + b"\x81\x80" + counts + question + answer
            connection.sendall(len(response).to_bytes(2, "big") + response)


def generate_issuer_transport_credentials(directory):
    def openssl(*args):
        result = subprocess.run(["openssl", *args], cwd=directory, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())

    openssl(
        "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=Rocky Pebble test CA",
        "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )
    openssl(
        "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-keyout", "pebble.key", "-out", "pebble.csr", "-subj", "/CN=localhost",
    )
    directory.joinpath("leaf.ext").write_text(
        "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n"
    )
    openssl(
        "x509", "-req", "-in", "pebble.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
        "-CAcreateserial", "-out", "pebble.pem", "-days", "1", "-extfile", "leaf.ext",
    )


def tcp_get(port, host, path="/", tls=None):
    with contextlib.ExitStack() as stack:
        stream = stack.enter_context(socket.create_connection(("127.0.0.1", port), timeout=2))
        credential = None
        if tls is not None:
            stream = stack.enter_context(tls.wrap_socket(stream, server_hostname=host))
            credential = stream.getpeercert(binary_form=True)
        stream.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        with http.client.HTTPResponse(stream, method="GET") as response:
            response.begin()
            return response.status, response.headers, response.read(), credential


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def fixture(args, directory, stack):
    issuer, management, plain, secure = available_ports(4)
    generate_issuer_transport_credentials(directory)
    dns = stack.enter_context(socket.socket())
    dns.bind(("127.0.0.1", 0))
    dns.listen(16)
    threading.Thread(target=serve_dns, args=(dns,), daemon=True).start()

    pebble_config = directory / "pebble.json"
    pebble_config.write_text(json.dumps({"pebble": {
        "listenAddress": f"127.0.0.1:{issuer}",
        "managementListenAddress": f"127.0.0.1:{management}",
        "certificate": str(directory / "pebble.pem"),
        "privateKey": str(directory / "pebble.key"),
        "httpPort": plain,
        "tlsPort": secure,
        "profiles": {"default": {"description": "Short-lived test certificate", "validityPeriod": 18}},
    }}))

    directory.joinpath("content").mkdir()
    directory.joinpath("content/index.html").write_text("rocky-acme-fixture")
    config = directory / "rocky.toml"
    config.write_text(f"""schema_version = 1
admin_socket = "admin.sock"
state_dir = "state"
drain_timeout = "2s"

[acme]
directory_url = "https://127.0.0.1:{issuer}/dir"
contact = "mailto:test@{HOST}"
accept_terms = true
trust_roots = "ca.pem"

[[listeners]]
name = "plain"
bind = "127.0.0.1:{plain}"
protocols = ["http1"]

[[listeners]]
name = "secure"
bind = "127.0.0.1:{secure}"
protocols = ["http1", "h2", "h3"]
tls = true

[[sites]]
host = "{HOST}"
listeners = ["plain", "secure"]
tls = "acme"
redirect_http = true

[[sites.routes]]
name = "files"
path_prefix = "/"
static_root = "content"
""")

    socket_path = directory / "admin.sock"
    state = directory / "state"
    rocky_log = stack.enter_context(directory.joinpath("rocky.log").open("ab"))
    pebble_log = stack.enter_context(directory.joinpath("pebble.log").open("ab"))

    def start_rocky():
        daemon = subprocess.Popen([args.rocky, "run", "--config", config], stdout=rocky_log, stderr=rocky_log)
        stack.callback(stop, daemon)
        wait_until("the administration socket", certificate)
        return daemon

    def certificate():
        result = subprocess.check_output(
            [args.rocky, "status", "--admin-socket", socket_path], stderr=subprocess.DEVNULL, timeout=3,
        )
        return json.loads(result)["certificates"]["secure"][HOST]

    def installed():
        status = certificate()
        return status if status["ready"] else None

    subprocess.run([args.rocky, "check", "--config", config], check=True, timeout=5)
    daemon = start_rocky()
    assert not certificate()["ready"]
    assert tcp_get(plain, HOST, "/?x=1")[0] == 503
    assert tcp_get(plain, HOST, CHALLENGE_PREFIX + "unknown")[0] == 503

    pebble = subprocess.Popen(
        [args.pebble, "-config", pebble_config, "-dnsserver", f"127.0.0.1:{dns.getsockname()[1]}"],
        env=dict(os.environ, PEBBLE_VA_NOSLEEP="1", PEBBLE_VA_ALWAYS_VALID="0", PEBBLE_WFE_NONCEREJECT="0", PEBBLE_AUTHZREUSE="0"),
        stdout=pebble_log, stderr=pebble_log,
    )
    stack.callback(stop, pebble)
    pebble_trust = ssl.create_default_context(cafile=directory / "ca.pem")
    _, _, issuer_root, _ = wait_until(
        "the Pebble issuer CA",
        lambda: tcp_get(management, "127.0.0.1", "/roots/0", pebble_trust),
    )
    trust = ssl.create_default_context(cadata=issuer_root.decode())

    if args.crash_after_finalize:
        logs = directory / "pebble.log"
        wait_until("Pebble to issue the finalized certificate", lambda: "Issued certificate serial" in logs.read_text())
        daemon.kill()
        daemon.wait(5)
        journal = list(state.glob("*.order.json"))
        assert len(journal) == 1 and not list(state.glob("*.bundle.json"))
        daemon = start_rocky()
        wait_until("the resumed certificate", installed)
        assert logs.read_text().count("There are now 1 orders in the db") == 1
        assert "There are now 2 orders in the db" not in logs.read_text()
        assert not journal[0].exists()
        print("Resumed the finalized order after a process kill", flush=True)

    first = wait_until("the issued certificate", installed)
    status, headers, body, certificate_before = tcp_get(secure, HOST, tls=trust)
    assert (status, body) == (200, b"rocky-acme-fixture")
    assert headers["alt-svc"].startswith(f'h3=":{secure}"')
    status, headers, _, _ = tcp_get(plain, HOST, "/path?q=1&x=2")
    assert status == 308 and headers["location"] == f"https://{HOST}:{secure}/path?q=1&x=2"
    print("Issued a trusted certificate through HTTP-01", flush=True)

    exchanges = 0
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        status, _, body, certificate_after = tcp_get(secure, HOST, tls=trust)
        assert (status, body) == (200, b"rocky-acme-fixture")
        exchanges += 1
        if certificate_after != certificate_before:
            break
        time.sleep(0.12)
    else:
        raise AssertionError("Certificate did not renew")
    renewed = certificate()
    assert renewed["orders_succeeded"] >= 2
    assert renewed["expires_at_unix"] > first["expires_at_unix"]
    print(f"Renewed during {exchanges} HTTPS exchanges", flush=True)

    stop(daemon)
    assert daemon.returncode == 0 and not socket_path.exists()
    start_rocky()
    restored = certificate()
    assert restored["ready"] and restored["orders_succeeded"] == 0
    assert restored["expires_at_unix"] == renewed["expires_at_unix"]
    status, _, body, restored_certificate = tcp_get(secure, HOST, tls=trust)
    assert (status, body, restored_certificate) == (200, b"rocky-acme-fixture", certificate_after)
    assert all(path.stat().st_mode & 0o077 == 0 for path in state.iterdir())
    print("Restored the renewed certificate from private state", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pebble", default="pebble", help="Pebble v2.10.1 or compatible executable")
    parser.add_argument("--rocky", type=Path, default=Path(__file__).resolve().parents[1] / "target/debug/rocky")
    parser.add_argument("--crash-after-finalize", action="store_true", help="Test recovery of an in-progress order")
    args = parser.parse_args()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="rocky-pebble-") as temporary:
        directory = Path(temporary)
        try:
            with contextlib.ExitStack() as stack:
                fixture(args, directory, stack)
        except Exception:
            for log in directory.glob("*.log"):
                print(f"Last lines from {log.name}")
                print("\n".join(log.read_text().splitlines()[-40:]))
            raise


if __name__ == "__main__":
    main()
