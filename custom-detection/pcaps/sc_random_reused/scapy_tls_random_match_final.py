#!/usr/bin/env python3
"""
基于 Scapy TLS 层构造 Client Random == Server Random 的异常握手 pcap
用于验证 Suricata 检测规则

字段名已在实际 Scapy 环境中逐一核实（TLSClientHello / TLSServerHello /
TLS_Ext_ServerName / ServerName / TLS_Ext_SupportedVersion_CH/SH）

依赖:
    pip install scapy cryptography

用法:
    python3 scapy_tls_random_match_final.py
"""

import os
from scapy.all import IP, TCP, wrpcap
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.extensions import (
    TLS_Ext_ServerName, ServerName,
    TLS_Ext_SupportedVersion_CH, TLS_Ext_SupportedVersion_SH,
)

CLIENT_IP, SERVER_IP = "192.168.56.101", "192.168.56.201"
CLIENT_PORT, SERVER_PORT = 51234, 443

# ---- 核心：一份 32 字节随机数，拆成 gmt_unix_time(4B) + random_bytes(28B) ----
# Scapy 的 TLSClientHello/TLSServerHello random 字段本质是这两部分拼接而成
# 所以要让两边的完整 random 相同，必须让 gmt_unix_time 和 random_bytes 都相同
same_random_full = os.urandom(32)
same_gmt = int.from_bytes(same_random_full[:4], "big")
same_rand_bytes = same_random_full[4:]

client_hello = TLS(msg=[
    TLSClientHello(
        gmt_unix_time=same_gmt,
        random_bytes=same_rand_bytes,
        ciphers=[0x1301, 0x1302, 0xc02f],
        ext=[
            TLS_Ext_ServerName(servernames=[ServerName(servername=b"example.com")]),
            TLS_Ext_SupportedVersion_CH(versions=[0x0304]),
        ],
    )
])

server_hello = TLS(msg=[
    TLSServerHello(
        gmt_unix_time=same_gmt,          # 与 client 完全相同
        random_bytes=same_rand_bytes,     # 与 client 完全相同
        cipher=0x1301,
        ext=[
            TLS_Ext_SupportedVersion_SH(version=0x0304),
        ],
    )
])

# ---- 构造 TCP 会话骨架（三次握手 + PSH/ACK 载荷）----
isn_c, isn_s = 1000, 5000
pkts = []

pkts.append(IP(src=CLIENT_IP, dst=SERVER_IP) /
            TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=isn_c))
pkts.append(IP(src=SERVER_IP, dst=CLIENT_IP) /
            TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="SA", seq=isn_s, ack=isn_c + 1))
pkts.append(IP(src=CLIENT_IP, dst=SERVER_IP) /
            TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=isn_c + 1, ack=isn_s + 1))

ch_bytes = bytes(client_hello)
pkts.append(IP(src=CLIENT_IP, dst=SERVER_IP) /
            TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="PA", seq=isn_c + 1, ack=isn_s + 1) /
            ch_bytes)

pkts.append(IP(src=SERVER_IP, dst=CLIENT_IP) /
            TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="A",
                seq=isn_s + 1, ack=isn_c + 1 + len(ch_bytes)))

sh_bytes = bytes(server_hello)
pkts.append(IP(src=SERVER_IP, dst=CLIENT_IP) /
            TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="PA",
                seq=isn_s + 1, ack=isn_c + 1 + len(ch_bytes)) /
            sh_bytes)

pkts.append(IP(src=CLIENT_IP, dst=SERVER_IP) /
            TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A",
                seq=isn_c + 1 + len(ch_bytes), ack=isn_s + 1 + len(sh_bytes)))

wrpcap("tls_random_match_scapy.pcap", pkts)
print("生成完成: tls_random_match_scapy.pcap")

# ---- 自校验：反解析生成的字节，确认两边 random 真的一致 ----
ch_parsed = TLS(ch_bytes)
sh_parsed = TLS(sh_bytes)

ch_gmt = ch_parsed.msg[0].gmt_unix_time
ch_rand = bytes(ch_parsed.msg[0].random_bytes)
sh_gmt = sh_parsed.msg[0].gmt_unix_time
sh_rand = bytes(sh_parsed.msg[0].random_bytes)

ch_full = ch_gmt.to_bytes(4, "big") + ch_rand
sh_full = sh_gmt.to_bytes(4, "big") + sh_rand

print("Client Random:", ch_full.hex())
print("Server Random:", sh_full.hex())
assert ch_full == sh_full, "random 不一致，检查构造逻辑！"
print("✅ 校验通过：Client Random == Server Random")