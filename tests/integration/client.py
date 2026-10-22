"""Client actions for the integration test (runs in the client namespace).

  client.py tls SNI IP        complete a TLS handshake and print the server reply
  client.py udp IP COUNT      send QUIC-Initial-shaped datagrams to IP:443
"""
import socket
import ssl
import struct
import sys

command = sys.argv[1]
if command == "tls":
    sni, ip = sys.argv[2], sys.argv[3]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, 443), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=sni) as tls:
            print(tls.recv(16).decode())
elif command == "udp":
    ip, count = sys.argv[2], int(sys.argv[3])
    # A minimal QUIC v1 Initial long header: 8-byte DCID, empty SCID and token, length covering the rest.
    body = 1250 - 1 - 4 - 1 - 8 - 1 - 1 - 2
    datagram = bytes([0xC3]) + struct.pack("!I", 1) + bytes([8]) + b"\x11" * 8 + b"\x00\x00" \
        + struct.pack("!H", 0x4000 | body) + b"\x22" * body
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(count):
        sock.sendto(datagram, (ip, 443))
    print(len(datagram))
else:
    sys.exit("unknown command")
