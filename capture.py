#!/usr/bin/env python3
"""
Projects: Network Packet Sniffer
Authors: Lucas Myers, Purvendra Bhatt, Jonathan Campbell
Course:CS4730
"""

from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, Raw
import time
import threading
from collections import Counter, defaultdict
import argparse

#Counts the stats globablly
PACKETS = 0
BYTES = 0
TOP_TALKERS = Counter()

# Store TCP streams for reassembly
TCP_STREAMS = defaultdict(list)


def parse_packet(pkt):
    """Parse and display packet headers, collect stats and TCP data."""
    global PACKETS, BYTES, TOP_TALKERS
    PACKETS += 1
    BYTES += len(pkt)
    timestamp = time.strftime("%H:%M:%S", time.localtime())

    src_ip = dst_ip = "-"
    src_port = dst_port = "-"
    proto_name = "-"
    flags = ""

    # Layer 2: Ethernet
    if Ether in pkt:
        eth = pkt[Ether]

    # Layer 3: IPv4 or IPv6
    if IP in pkt:
        ip = pkt[IP]
        src_ip, dst_ip = ip.src, ip.dst
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        src_ip, dst_ip = ip.src, ip.dst

    # Layer 4: TCP or UDP
    if TCP in pkt:
        tcp = pkt[TCP]
        src_port, dst_port = tcp.sport, tcp.dport
        proto_name = "TCP"
        flags = str(tcp.flags)
        handle_tcp_reassembly(pkt, src_ip, dst_ip, src_port, dst_port, tcp)
    elif UDP in pkt:
        udp = pkt[UDP]
        src_port, dst_port = udp.sport, udp.dport
        proto_name = "UDP"
        handle_udp_detection(pkt, src_ip, dst_ip, src_port, dst_port)
    else:
        proto_name = "Other"

    # Count top talkers
    TOP_TALKERS[src_ip] += 1

    # Print summary line
    print(f"[{timestamp}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} {proto_name} len={len(pkt)} flags={flags}")


def handle_tcp_reassembly(pkt, src_ip, dst_ip, sport, dport, tcp):
    """Collect TCP payloads by stream key and try to reassemble HTTP."""
    key = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))
    if Raw in pkt:
        payload = pkt[Raw].load
        TCP_STREAMS[key].append(payload)
        # Try simple HTTP detection
        if b"HTTP/" in payload or payload.startswith(b"GET") or payload.startswith(b"POST"):
            data = b"".join(TCP_STREAMS[key])
            try:
                text = data.decode(errors="ignore")
                if "Host:" in text or "HTTP/" in text:
                    print("\n=== HTTP Stream Detected ===")
                    print(text.split("\r\n\r\n")[0])  # print headers only
                    print("===========================\n")
            except Exception:
                pass


def handle_udp_detection(pkt, src_ip, dst_ip, sport, dport):
    """Check for encrypted UDP traffic like QUIC."""
    length = len(pkt)
    if dport == 443 or sport == 443:
        print(f"[!] Possible QUIC traffic detected between {src_ip} and {dst_ip} (UDP/443, {length} bytes)")


def detect_encrypted_traffic(pkt):
    """Detect HTTPS by port and TLS handshake bytes."""
    if TCP in pkt:
        t = pkt[TCP]
        if t.dport == 443 or t.sport == 443:
            if Raw in pkt and pkt[Raw].load.startswith(b"\x16\x03"):
                print(f"[!] TLS Handshake detected on {pkt[IP].src}:{t.sport} -> {pkt[IP].dst}:{t.dport}")


def stats_loop():
    """Print live stats every few seconds."""
    last_packets = 0
    last_bytes = 0
    while True:
        time.sleep(3)
        pps = PACKETS - last_packets
        bps = BYTES - last_bytes
        last_packets, last_bytes = PACKETS, BYTES
        print(f"\n[Stats] Packets={PACKETS}  Bytes={BYTES}  Rate={pps/3:.1f} pkts/s  {bps/3:.1f} B/s")
        if TOP_TALKERS:
            top = TOP_TALKERS.most_common(3)
            print(f"Top talkers: {top}\n")


def main():
    parser = argparse.ArgumentParser(description="Milestone 2 Packet Sniffer")
    parser.add_argument("-i", "--iface", required=True, help="Interface to capture packets on (e.g. eth0, lo)")
    parser.add_argument("--filter", help="Optional BPF filter (e.g. 'tcp port 80')")
    args = parser.parse_args()

    print("Starting Packet Capture...")
    print(f"Interface: {args.iface}")
    if args.filter:
        print(f"Filter: {args.filter}")
    print("Press Ctrl+C to stop.\n")

    # Start stats thread
    threading.Thread(target=stats_loop, daemon=True).start()

    try:
        sniff(iface=args.iface, filter=args.filter, prn=parse_packet, store=False)
    except KeyboardInterrupt:
        print("\nCapture stopped.")
        print(f"Total Packets: {PACKETS}")
        print(f"Total Bytes: {BYTES}")
        print(f"Top talkers: {TOP_TALKERS.most_common(5)}")
        print("Goodbye!")


if __name__ == "__main__":
    main()

