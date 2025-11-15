#!/usr/bin/env python3
"""
Milestone 2 Packet Sniffer
Lucas Myers, Purvendra, Jon
"""

# i just imported everything
from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, Raw

import time
import threading
from collections import Counter, defaultdict
import argparse

# global variables
PACKETS = 0
BYTES = 0
TOP_TALKERS = Counter()
TCP_STREAMS = defaultdict(list)



def parse_packet(packet):
    """ Everytime there is a packet this will run """
    global PACKETS, BYTES, TOP_TALKERS

    PACKETS += 1
    BYTES += len(packet)

    timestamp = time.strftime("%H:%M:%S", time.localtime())

    # default stuff so it doesnt explode
    src_ip = "-"
    dst_ip = "-"
    src_port = "-"
    dst_port = "-"
    proto = "-"
    flags = ""

    # ethernet 
    if Ether in packet:
        eth = packet[Ether]

    # try ipv4 then ipv6
    if IP in packet:
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
    elif IPv6 in packet:
        ip = packet[IPv6]
        src_ip = ip.src
        dst_ip = ip.dst

    # tcp or udp 
    if TCP in packet:
        tcp = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        proto = "TCP"
        flags = str(tcp.flags)
        handle_tcp_reassembly(packet, src_ip, dst_ip, src_port, dst_port, tcp)
    elif UDP in packet:
        udp = packet[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        proto = "UDP"
        handle_udp_detection(packet, src_ip, dst_ip, src_port, dst_port)
    else:
        proto = "Other???"

    TOP_TALKERS[src_ip] += 1

    # prints everything on one line 
    print(f"[{timestamp}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} {proto} len={len(packet)} flags={flags}")



def handle_tcp_reassembly(packet, src_ip, dst_ip, sport, dport, tcp):
    """ tries to rebuild http  """
    key = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))

    if Raw in packet:
        p = packet[Raw].load
        TCP_STREAMS[key].append(p)

        if b"HTTP/" in p or p.startswith(b"GET") or p.startswith(b"POST"):
            try:
                blob = b"".join(TCP_STREAMS[key]).decode(errors="ignore")
                if "Host:" in blob:
                    print("\n-HTTP Stream-m ")
                    print(blob.split("\r\n\r\n")[0])
                    print("-end-\n")
            except:
                pass



def handle_udp_detection(packet, src_ip, dst_ip, sport, dport):
    """ Will check to see if it is Quic or on port 443 """
    if sport == 443 or dport == 443:
        print(f"[!] might be QUIC or encrypted between {src_ip} and {dst_ip}")



def stats_loop():
    """  Will loop and print the stats every 3 seconds while the program is runing """
    lastp = 0
    lastb = 0
    while True:
        time.sleep(3)
        pps = PACKETS - lastp
        bps = BYTES - lastb
        lastp, lastb = PACKETS, BYTES

        print(f"\n[Stats] packets={PACKETS} bytes={BYTES} rate={pps/3:.2f}pps {bps/3:.2f}Bps")
        if TOP_TALKERS:
            print("top talkers:", TOP_TALKERS.most_common(3), "\n")



def main():
    parser = argparse.ArgumentParser(description="Milestone2 Sniffer")
    parser.add_argument("-i", "--iface", required=True, help="interface(eth0, wifi)")
    parser.add_argument("--filter", help="BPF filter if u wanna look fancy")
    args = parser.parse_args()

    print("Starting capture on", args.iface)
    if args.filter:
        print("Using filter:", args.filter)
    print("Ctrl+C to stop it (please don't unplug your pc)\n")

    # stats thread
    threading.Thread(target=stats_loop, daemon=True).start()

    try:
        sniff(iface=args.iface, filter=args.filter, prn=parse_packet, store=False)
    except KeyboardInterrupt:
        print("\nOkay stopping now")
        print("Total packets:", PACKETS)
        print("Total bytes:", BYTES)
        print("Top talkers:", TOP_TALKERS.most_common(5))
        print("bye.")



if __name__ == "__main__":
    main()


