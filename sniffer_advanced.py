#!/usr/bin/env python3
import sys
import argparse
from datetime import datetime
from scapy.all import ARP, ICMP, IP, Raw, TCP, UDP, sniff

class NetworkSniffer:
    def __init__(self):
        self.packet_count = 0
        self.stats = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'ARP': 0,
            'Other': 0
        }
    
    def display_payload(self, payload):
        """Afficher le payload"""
        try:
            decoded = payload.decode('utf-8', errors='ignore')
            if decoded.strip():
                print(f"  Payload: {decoded[:150]}...")
        except (UnicodeError, AttributeError):
            print(f"  Payload (Hex): {payload.hex()[:150]}...")
    
    def analyze_packet(self, packet):
        """Analyser un paquet"""
        self.packet_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        print(f"\n[{timestamp}] Paquet #{self.packet_count}")
        print("-" * 50)
        
        if IP in packet:
            ip = packet[IP]
            print(f"  Source: {ip.src}:", end="")
            print(f"  Dest: {ip.dst}")
            print(f"  TTL: {ip.ttl}")
            
            if TCP in packet:
                tcp = packet[TCP]
                print(f"  Protocole: TCP {tcp.sport}->{tcp.dport}")
                self.stats['TCP'] += 1
                if Raw in packet:
                    self.display_payload(packet[Raw].load)
                    
            elif UDP in packet:
                udp = packet[UDP]
                print(f"  Protocole: UDP {udp.sport}->{udp.dport}")
                self.stats['UDP'] += 1
                if Raw in packet:
                    self.display_payload(packet[Raw].load)
                    
            elif ICMP in packet:
                icmp = packet[ICMP]
                print(f"  Protocole: ICMP Type:{icmp.type} Code:{icmp.code}")
                self.stats['ICMP'] += 1
            else:
                self.stats['Other'] += 1
        elif ARP in packet:
            self.stats['ARP'] += 1
        else:
            self.stats['Other'] += 1
    
    def display_stats(self):
        """Afficher les statistiques"""
        print("\n" + "="*50)
        print("STATISTIQUES DE CAPTURE")
        print("="*50)
        print(f"Total paquets: {self.packet_count}")
        print(f"TCP: {self.stats['TCP']}")
        print(f"UDP: {self.stats['UDP']}")
        print(f"ICMP: {self.stats['ICMP']}")
        print(f"ARP: {self.stats['ARP']}")
        print(f"Autres: {self.stats['Other']}")
        print("="*50)
    
    def start(self, count=0, timeout=None, packet_filter=None, interface=None):
        """Démarrer le sniffer"""
        print("Sniffer avancé - Appuyez sur Ctrl+C pour arrêter\n")
        
        try:
            sniff(
                prn=self.analyze_packet,
                count=count if count > 0 else None,
                timeout=timeout,
                filter=packet_filter,
                iface=interface,
                store=False
            )
        except KeyboardInterrupt:
            print("\nArrêt demandé...")
        finally:
            self.display_stats()

def main():
    parser = argparse.ArgumentParser(description="Sniffer réseau avancé")
    parser.add_argument('-c', '--count', type=int, default=0,
                       help="Nombre de paquets à capturer")
    parser.add_argument('-t', '--timeout', type=int, default=None,
                       help="Timeout en secondes")
    parser.add_argument('-f', '--filter', type=str, default=None,
                       help="Filtre BPF (ex: 'tcp', 'port 80')")
    parser.add_argument('-i', '--interface', type=str, default=None,
                       help="Interface réseau à écouter")
    
    args = parser.parse_args()
    
    sniffer = NetworkSniffer()
    if args.count < 0 or (args.timeout is not None and args.timeout < 0):
        parser.error("--count et --timeout doivent être positifs ou nuls")
    sniffer.start(
        count=args.count,
        timeout=args.timeout,
        packet_filter=args.filter,
        interface=args.interface,
    )

if __name__ == "__main__":
    main()
