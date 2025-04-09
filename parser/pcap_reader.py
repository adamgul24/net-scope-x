
import pyshark
import csv
from pathlib import Path

def parse_pcap(pcap_file, output_csv):
    cap = pyshark.FileCapture(pcap_file, use_json=True)

    features = []
    for packet in cap:
        try:
            timestamp = packet.sniff_time.isoformat()
            protocol = packet.highest_layer
            src_ip = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
            length = packet.length if hasattr(packet, 'length') else 'N/A'
            info = str(packet)

            features.append([timestamp, protocol, src_ip, dst_ip, length, info])
        except Exception as e:
            continue

    cap.close()

    headers = ['Timestamp', 'Protocol', 'Src_IP', 'Dst_IP', 'Length', 'Raw_Info']
    with open(output_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(features)

    print(f"[+] Extracted {len(features)} packets to {output_csv}")
