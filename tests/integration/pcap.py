"""Inspects IPv4 packets towards a destination in a tcpdump capture (Ethernet link type).

  pcap.py FILE DEST tcp        one line per TCP segment with payload: "seq length checksum_ok"
  pcap.py FILE DEST udp        one line per UDP datagram or fragment: "id offset more_fragments length"
  pcap.py FILE DEST standard   exit 0 if a ClientHello was split with the 2-byte head sent after the tail
  pcap.py FILE DEST unsplit    exit 0 if the ClientHello left in one piece
  pcap.py FILE DEST fakesplit  exit 0 if a bad-checksum fake preceded a forward-order real split
"""
import struct
import sys

TLS_RECORD = bytes([0x16, 0x03])


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def packets(path, destination):
    with open(path, "rb") as f:
        magic = f.read(24)[:4]
        endian = "<" if magic in (bytes([0xD4, 0xC3, 0xB2, 0xA1]), bytes([0x4D, 0x3C, 0xB2, 0xA1])) else ">"
        while header := f.read(16):
            _, _, length, _ = struct.unpack(endian + "IIII", header)
            frame = f.read(length)
            if len(frame) <= 34 or frame[12:14] != bytes([0x08, 0x00]):
                continue
            ip = frame[14:]
            if ip[0] >> 4 == 4 and ".".join(map(str, ip[16:20])) == destination:
                yield ip[:struct.unpack("!H", ip[2:4])[0]]


def segments(path, destination):
    """(seq, payload length, checksum valid, first payload bytes) for TCP segments that carry data."""
    result = []
    for ip in packets(path, destination):
        if ip[9] != 6:
            continue
        tcp = ip[(ip[0] & 15) * 4:]
        payload = tcp[(tcp[12] >> 4) * 4:]
        if payload and not tcp[13] & 0x02:
            pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
            result.append((struct.unpack("!I", tcp[4:8])[0], len(payload), checksum(pseudo + tcp) == 0xFFFF, payload[:2]))
    return result


def verdict(data, mode):
    if mode == "unsplit":
        hello = next((s for s in data if s[3] == TLS_RECORD), None)
        return hello is not None and hello[1] > 100 and all(s[1] != 2 for s in data)
    if mode == "standard":
        for i, (seq, length, valid, _) in enumerate(data):
            if length == 2 and valid and i > 0:
                tail = data[i - 1]
                return tail[0] == (seq + 2) & 0xFFFFFFFF and tail[2]
        return False
    if mode == "fakesplit":
        for i, (seq, length, valid, _) in enumerate(data):
            if not valid:
                real = [s for s in data[i + 1:i + 4] if s[2]]
                if len(real) < 2 or real[0][0] != seq or real[0][1] >= length:
                    return False
                return real[1][0] == (seq + real[0][1]) & 0xFFFFFFFF and real[0][1] + real[1][1] == length
        return False
    raise SystemExit("unknown mode: " + mode)


path, destination, mode = sys.argv[1], sys.argv[2], sys.argv[3]
if mode == "tcp":
    for seq, length, valid, _ in segments(path, destination):
        print(seq, length, int(valid))
elif mode == "udp":
    for ip in packets(path, destination):
        if ip[9] == 17:
            flags_offset = struct.unpack("!H", ip[6:8])[0]
            print(struct.unpack("!H", ip[4:6])[0], (flags_offset & 0x1FFF) * 8, int(bool(flags_offset & 0x2000)),
                  len(ip) - (ip[0] & 15) * 4)
else:
    sys.exit(0 if verdict(segments(path, destination), mode) else 1)
