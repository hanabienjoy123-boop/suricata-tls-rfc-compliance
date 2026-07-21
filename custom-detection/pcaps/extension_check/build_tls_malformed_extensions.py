#!/usr/bin/env python3
"""
构造一个畸形 TLS 握手，同时触发以下 5 条规则：

  sid:1000002  duplicate extension types in Hello
               -> ClientHello 里 server_name(0x0000) 出现两次

  sid:1000006  pre_shared_key extension not last in ClientHello
               -> ClientHello 里 pre_shared_key(0x0029) 后面还有别的扩展

  sid:1000003  server negotiated GREASE extension
               -> ServerHello 里塞一个 GREASE 值 (0x0a0a)

  sid:1000004  server sent unproposed extension
               -> ServerHello 里带 ALPN(0x0010)，但 ClientHello 从未提议过

  sid:1000005  server sent disallowed signature_algorithms
               -> ServerHello 里塞 signature_algorithms(0x000d)

纯标准库实现（struct 手工拼字节），不依赖 scapy.layers.tls 的高层 API，
因为这些畸形结构（重复扩展、乱序、跨端非法扩展）用标准 TLS 库/高层封装
基本无法直接表达，必须手工控制字节。

用法:
    python3 build_tls_malformed_extensions.py
"""

import struct
import socket
import os
import time

# ---------- 网络参数 ----------
CLIENT_IP = "192.168.56.101"
SERVER_IP = "192.168.56.201"
CLIENT_PORT = 51234
SERVER_PORT = 443

CLIENT_MAC = bytes.fromhex("0242ac110001")
SERVER_MAC = bytes.fromhex("0242ac110002")

# ---------- 通用: 校验和 / 头部构造 ----------
def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

def ip_header(src, dst, payload_len, ident, ttl=64, proto=6):
    ver_ihl = (4 << 4) | 5
    total_len = 20 + payload_len
    flags_frag = 0x4000
    hdr = struct.pack("!BBHHHBBH4s4s",
                       ver_ihl, 0, total_len, ident, flags_frag,
                       ttl, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst))
    csum = checksum(hdr)
    return hdr[:10] + struct.pack("!H", csum) + hdr[12:]

def tcp_header(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload, window=64240):
    offset_res = (5 << 4)
    hdr = struct.pack("!HHIIBBHHH",
                       src_port, dst_port, seq, ack,
                       offset_res, flags, window, 0, 0)
    pseudo = struct.pack("!4s4sBBH",
                          socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
                          0, 6, len(hdr) + len(payload))
    csum = checksum(pseudo + hdr + payload)
    return hdr[:16] + struct.pack("!H", csum) + hdr[18:]

def eth_header(src_mac, dst_mac, ethertype=0x0800):
    return dst_mac + src_mac + struct.pack("!H", ethertype)

FLAG_SYN, FLAG_ACK, FLAG_PSH = 0x02, 0x10, 0x08

def build_packet(src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port,
                  seq, ack, flags, payload, ident):
    tcp = tcp_header(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
    ip = ip_header(src_ip, dst_ip, len(tcp) + len(payload), ident)
    eth = eth_header(src_mac, dst_mac)
    return eth + ip + tcp + payload

def body_len_3(n: int) -> bytes:
    return struct.pack("!I", n)[1:]

def ext(ext_type: int, data: bytes) -> bytes:
    """构造单个 TLS extension 的 TLV: type(2B) + length(2B) + data"""
    return struct.pack("!HH", ext_type, len(data)) + data

# ---------- 各扩展的 payload 构造 ----------
def build_sni_ext_data(hostname: bytes) -> bytes:
    entry = b"\x00" + struct.pack("!H", len(hostname)) + hostname
    return struct.pack("!H", len(entry)) + entry

def build_supported_versions_ch(versions: list) -> bytes:
    body = b"".join(struct.pack("!H", v) for v in versions)
    return struct.pack("!B", len(body)) + body

def build_supported_versions_sh(version: int) -> bytes:
    return struct.pack("!H", version)

def build_psk_ext_data(identity: bytes) -> bytes:
    """RFC8446 4.2.11 pre_shared_key (ClientHello 形态), 塞一个假的身份+binder"""
    identity_entry = struct.pack("!H", len(identity)) + identity + struct.pack("!I", 0)
    identities = struct.pack("!H", len(identity_entry)) + identity_entry
    binder = os.urandom(32)
    binder_entry = struct.pack("!B", len(binder)) + binder
    binders = struct.pack("!H", len(binder_entry)) + binder_entry
    return identities + binders

def build_alpn_ext_data(protocols: list) -> bytes:
    entries = b"".join(struct.pack("!B", len(p)) + p for p in protocols)
    return struct.pack("!H", len(entries)) + entries

def build_sig_algos_ext_data(algos: list) -> bytes:
    body = b"".join(struct.pack("!H", a) for a in algos)
    return struct.pack("!H", len(body)) + body

# ---------- ClientHello ----------
def build_client_hello() -> bytes:
    cipher_suites = struct.pack("!H", 0x1301) + struct.pack("!H", 0x1302)
    compression_methods = b"\x00"
    session_id = b""

    sni_ext_data = build_sni_ext_data(b"example.com")
    sv_ext_data = build_supported_versions_ch([0x0304])
    psk_ext_data = build_psk_ext_data(b"test-psk-identity")
    padding_ext_data = b"\x00" * 10  # padding(0x0015), 内容无意义, 只为放在 psk 之后

    # 关键: 扩展排列顺序
    #   1. server_name          (0x0000)
    #   2. supported_versions   (0x002b)
    #   3. pre_shared_key       (0x0029)   <- 必须是最后一个才合规
    #   4. padding              (0x0015)   <- 但这里排在 psk 后面，违反 RFC8446 4.2.11 -> sid:1000006
    #   5. server_name          (0x0000)   <- 重复扩展类型 -> sid:1000002
    extensions = (
        ext(0x0000, sni_ext_data) +
        ext(0x002b, sv_ext_data) +
        ext(0x0029, psk_ext_data) +
        ext(0x0015, padding_ext_data) +
        ext(0x0000, sni_ext_data)       # 重复的 server_name
    )

    body = struct.pack("!H", 0x0303)               # legacy client_version
    body += os.urandom(32)                          # random
    body += struct.pack("!B", len(session_id)) + session_id
    body += struct.pack("!H", len(cipher_suites)) + cipher_suites
    body += struct.pack("!B", len(compression_methods)) + compression_methods
    body += struct.pack("!H", len(extensions)) + extensions

    handshake = struct.pack("!B", 0x01) + body_len_3(len(body)) + body
    record = struct.pack("!B", 0x16) + struct.pack("!H", 0x0301) + struct.pack("!H", len(handshake)) + handshake
    return record

# ---------- ServerHello ----------
def build_server_hello() -> bytes:
    session_id = os.urandom(32)
    cipher_suite = struct.pack("!H", 0x1301)
    compression_method = b"\x00"

    sv_ext_data = build_supported_versions_sh(0x0304)
    grease_ext_data = b"\x00"                       # GREASE 扩展本身内容不重要，重要的是 type
    alpn_ext_data = build_alpn_ext_data([b"h2"])      # client 从未提议过 ALPN -> sid:1000004
    sig_algos_ext_data = build_sig_algos_ext_data([0x0403])  # server 不该发这个 -> sid:1000005

    # GREASE 扩展类型取值需符合 RFC8701 §3 的 0x?A?A 模式, 这里用 0x0a0a
    GREASE_EXT_TYPE = 0x0a0a

    extensions = (
        ext(0x002b, sv_ext_data) +
        ext(GREASE_EXT_TYPE, grease_ext_data) +      # -> sid:1000003
        ext(0x0010, alpn_ext_data) +                  # -> sid:1000004
        ext(0x000d, sig_algos_ext_data)                # -> sid:1000005
    )

    body = struct.pack("!H", 0x0303)
    body += os.urandom(32)
    body += struct.pack("!B", len(session_id)) + session_id
    body += cipher_suite
    body += compression_method
    body += struct.pack("!H", len(extensions)) + extensions

    handshake = struct.pack("!B", 0x02) + body_len_3(len(body)) + body
    record = struct.pack("!B", 0x16) + struct.pack("!H", 0x0303) + struct.pack("!H", len(handshake)) + handshake
    return record

# ---------- pcap 写入 ----------
def pcap_global_header():
    return struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def pcap_record(pkt_bytes, ts):
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000)
    return struct.pack("<IIII", sec, usec, len(pkt_bytes), len(pkt_bytes)) + pkt_bytes

def main():
    client_hello = build_client_hello()
    server_hello = build_server_hello()

    isn_c, isn_s = 1_000_000, 5_000_000
    now = time.time()
    packets = []

    packets.append(build_packet(CLIENT_IP, SERVER_IP, CLIENT_MAC, SERVER_MAC,
                                 CLIENT_PORT, SERVER_PORT, isn_c, 0, FLAG_SYN, b"", ident=1))
    packets.append(build_packet(SERVER_IP, CLIENT_IP, SERVER_MAC, CLIENT_MAC,
                                 SERVER_PORT, CLIENT_PORT, isn_s, isn_c + 1, FLAG_SYN | FLAG_ACK, b"", ident=1))
    packets.append(build_packet(CLIENT_IP, SERVER_IP, CLIENT_MAC, SERVER_MAC,
                                 CLIENT_PORT, SERVER_PORT, isn_c + 1, isn_s + 1, FLAG_ACK, b"", ident=2))

    packets.append(build_packet(CLIENT_IP, SERVER_IP, CLIENT_MAC, SERVER_MAC,
                                 CLIENT_PORT, SERVER_PORT, isn_c + 1, isn_s + 1,
                                 FLAG_PSH | FLAG_ACK, client_hello, ident=3))
    packets.append(build_packet(SERVER_IP, CLIENT_IP, SERVER_MAC, CLIENT_MAC,
                                 SERVER_PORT, CLIENT_PORT, isn_s + 1, isn_c + 1 + len(client_hello),
                                 FLAG_ACK, b"", ident=2))
    packets.append(build_packet(SERVER_IP, CLIENT_IP, SERVER_MAC, CLIENT_MAC,
                                 SERVER_PORT, CLIENT_PORT, isn_s + 1, isn_c + 1 + len(client_hello),
                                 FLAG_PSH | FLAG_ACK, server_hello, ident=3))
    packets.append(build_packet(CLIENT_IP, SERVER_IP, CLIENT_MAC, SERVER_MAC,
                                 CLIENT_PORT, SERVER_PORT, isn_c + 1 + len(client_hello),
                                 isn_s + 1 + len(server_hello), FLAG_ACK, b"", ident=4))

    out_path = "/mnt/user-data/outputs/tls_malformed_extensions.pcap"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(pcap_global_header())
        for i, pkt in enumerate(packets):
            f.write(pcap_record(pkt, now + i * 0.001))

    print(f"生成完成: {out_path}")
    print(f"数据包数量: {len(packets)}")
    print(f"ClientHello 长度: {len(client_hello)} bytes")
    print(f"ServerHello 长度: {len(server_hello)} bytes")

if __name__ == "__main__":
    main()
