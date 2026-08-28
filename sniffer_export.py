#!/usr/bin/env python3
import json
import csv
import argparse
from datetime import datetime

from scapy.all import IP, TCP, UDP

from sniffer_advanced import NetworkSniffer

class SnifferWithExport(NetworkSniffer):
    def __init__(self):
        super().__init__()
        self.packets_data = []
    
    def analyze_packet(self, packet):
        super().analyze_packet(packet)
        
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'number': self.packet_count
        }
        
        if IP in packet:
            ip = packet[IP]
            packet_info.update({
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'ttl': ip.ttl,
                'protocol': self.get_protocol_name(ip.proto)
            })
            
            if TCP in packet:
                tcp = packet[TCP]
                packet_info.update({
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'flags': str(tcp.flags)
                })
            elif UDP in packet:
                udp = packet[UDP]
                packet_info.update({
                    'src_port': udp.sport,
                    'dst_port': udp.dport
                })
        
        self.packets_data.append(packet_info)
    
    def get_protocol_name(self, proto_num):
        protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP'}
        return protocols.get(proto_num, f'Unknown({proto_num})')
    
    def export_json(self, filename='capture.json'):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.packets_data, f, indent=2)
        print(f"Exporté vers {filename}")
    
    def export_csv(self, filename='capture.csv'):
        if not self.packets_data:
            print("Aucune donnée à exporter")
            return
        
        keys = sorted({key for packet in self.packets_data for key in packet})
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.packets_data)
        print(f"Exporté vers {filename}")

def main():
    parser = argparse.ArgumentParser(description="Capture réseau avec export JSON ou CSV.")
    parser.add_argument('-c', '--count', type=int, default=10,
                        help="Nombre de paquets à capturer (0 = en continu)")
    parser.add_argument('-t', '--timeout', type=int, default=None,
                        help="Durée maximale de capture en secondes")
    parser.add_argument('-f', '--filter', default=None, help="Filtre BPF Scapy")
    parser.add_argument('-i', '--interface', default=None, help="Interface réseau")
    parser.add_argument('-o', '--output', default='capture.json',
                        help="Fichier de sortie (.json ou .csv)")
    args = parser.parse_args()

    if args.count < 0 or (args.timeout is not None and args.timeout < 0):
        parser.error("--count et --timeout doivent être positifs ou nuls")

    sniffer = SnifferWithExport()
    sniffer.start(args.count, args.timeout, args.filter, args.interface)
    if args.output.lower().endswith('.csv'):
        sniffer.export_csv(args.output)
    else:
        sniffer.export_json(args.output)


if __name__ == '__main__':
    main()
