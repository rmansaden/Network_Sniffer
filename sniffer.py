#!/usr/bin/env python3
import argparse
import sys

from scapy.all import ICMP, IP, Raw, TCP, UDP, sniff

def display_payload(payload):
    """Affiche les 150 premiers caractères du payload."""
    decoded = payload.decode("utf-8", errors="ignore")
    if decoded.strip():
        print(f"Payload (UTF-8): {decoded[:150]}")
    else:
        print(f"Payload (Hex): {payload.hex()[:150]}")

def analyze_packet(packet):
    """Analyse complète du paquet"""
    
    print("\n" + "="*70)
    
    if IP in packet:
        ip = packet[IP]
        print(f"IP Source: {ip.src}  |  IP Dest: {ip.dst}")
        print(f"TTL: {ip.ttl}  |  Longueur: {ip.len} octets")
        
        if TCP in packet:
            tcp = packet[TCP]
            print(f"[TCP] {tcp.sport} -> {tcp.dport} | Flags: {tcp.flags}")
            
            if Raw in packet:
                display_payload(packet[Raw].load)
                
        elif UDP in packet:
            udp = packet[UDP]
            print(f"[UDP] {udp.sport} -> {udp.dport}")
            
            if Raw in packet:
                display_payload(packet[Raw].load)
                
        elif ICMP in packet:
            icmp = packet[ICMP]
            print(f"[ICMP] Type: {icmp.type} | Code: {icmp.code}")
    
    else:
        print("Paquet non-IP")
    
    print("="*70)

def main():
    parser = argparse.ArgumentParser(description="Capture et affiche les paquets réseau.")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Nombre de paquets à capturer (0 = en continu)")
    parser.add_argument("-t", "--timeout", type=int, default=None,
                        help="Durée maximale de capture en secondes")
    parser.add_argument("-f", "--filter", default=None,
                        help="Filtre BPF Scapy, par exemple: 'tcp port 443'")
    parser.add_argument("-i", "--interface", default=None,
                        help="Interface réseau à écouter")
    args = parser.parse_args()

    if args.count < 0 or (args.timeout is not None and args.timeout < 0):
        parser.error("--count et --timeout doivent être positifs ou nuls")

    print("""
    =========================================
    NETWORK SNIFFER - Stage CodeAlfa 2026
    =========================================
    """)
    
    try:
        sniff(
            prn=analyze_packet,
            count=args.count or 0,
            timeout=args.timeout,
            filter=args.filter,
            iface=args.interface,
            store=False,
        )
        
    except KeyboardInterrupt:
        print("\n\nArrêt du sniffer...")
        sys.exit(0)
    except (PermissionError, OSError) as error:
        print(f"Erreur de capture: {error}. Essayez avec sudo.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
