"""Test servers for the network-namespace integration test.

Runs inside the server namespace:
  * DoH (RFC 8484 POST) on 10.77.0.2:443 -- target.test and subdomains resolve to 10.77.0.3, other names to 10.77.0.98
  * plain UDP DNS on 10.77.0.2:53 -- every name resolves to 10.77.0.99 (the "unprotected" answer)
  * TLS on 10.77.0.3:443 and 10.77.0.4:443 -- logs the SNI of each completed handshake
  * UDP on 10.77.0.3:443 and 10.77.0.4:443 -- logs the size of every datagram
"""
import http.server
import socket
import socketserver
import ssl
import struct
import sys
import threading

CERTS = sys.argv[1]
LOG = open(sys.argv[2], "a", buffering=1)
LOCK = threading.Lock()


def log(line):
    with LOCK:
        LOG.write(line + "\n")


def answer(query, address):
    labels, pos = [], 12
    while query[pos]:
        length = query[pos]
        labels.append(query[pos + 1:pos + 1 + length].decode())
        pos += length + 1
    name = ".".join(labels).lower()
    qtype, = struct.unpack("!H", query[pos + 1:pos + 3])
    question = query[12:pos + 5]
    count = 1 if qtype == 1 else 0
    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, count, 0, 0)
    record = b""
    if count:
        ip = address(name) if callable(address) else address
        record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return name, header + question + record


def doh_address(name):
    return "10.77.0.3" if name == "target.test" or name.endswith(".target.test") else "10.77.0.98"


class DohHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        query = self.rfile.read(int(self.headers["Content-Length"]))
        name, reply = answer(query, doh_address)
        log(f"doh {name}")
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *args):
        pass


class ThreadingHttps(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def serve_doh():
    server = ThreadingHttps(("10.77.0.2", 443), DohHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(f"{CERTS}/doh.pem", f"{CERTS}/doh.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def serve_plain_dns():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("10.77.0.2", 53))
    while True:
        query, peer = sock.recvfrom(4096)
        name, reply = answer(query, "10.77.0.99")
        log(f"plain {name}")
        sock.sendto(reply, peer)


def serve_tls(address):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(f"{CERTS}/site.pem", f"{CERTS}/site.key")
    names = {}
    context.sni_callback = lambda conn, name, ctx: names.__setitem__(id(conn), name)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, 443))
    listener.listen(16)
    while True:
        conn, _ = listener.accept()
        try:
            tls = context.wrap_socket(conn, server_side=True)
            log(f"tls {address} {names.get(id(tls), '-')}")
            tls.sendall(b"OK")
            tls.close()
        except (ssl.SSLError, OSError) as error:
            log(f"tls-error {address} {error}")
            conn.close()


def serve_udp(address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, 443))
    while True:
        data, _ = sock.recvfrom(65535)
        log(f"udp {address} {len(data)}")


threads = [threading.Thread(target=serve_doh), threading.Thread(target=serve_plain_dns)]
for ip in ("10.77.0.3", "10.77.0.4"):
    threads += [threading.Thread(target=serve_tls, args=(ip,)), threading.Thread(target=serve_udp, args=(ip,))]
for thread in threads:
    thread.daemon = True
    thread.start()
log("ready")
threading.Event().wait()
