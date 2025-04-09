
import argparse
import os
from parser.pcap_reader import parse_pcap
from parser.suricata_analyzer import load_suricata_alerts
from visualizer.traffic_plot import generate_protocol_pie
import pandas as pd

def tag_csv_with_alerts(csv_path, alerts, tagged_csv_path):
    df = pd.read_csv(csv_path)
    df["Label"] = "benign"

    for alert in alerts:
        df.loc[
            (df["Src_IP"] == alert["src_ip"]) & (df["Dst_IP"] == alert["dest_ip"]),
            "Label"
        ] = "malicious"

    df.to_csv(tagged_csv_path, index=False)
    print(f"[+] Tagged CSV with labels saved to {tagged_csv_path}")

def main():
    parser = argparse.ArgumentParser(description="Wireshark Traffic Analyzer")
    parser.add_argument("--pcap", required=True, help="Path to PCAP file")
    parser.add_argument("--suricata", help="Path to Suricata eve.json log")
    parser.add_argument("--out", default="output/extracted.csv", help="Path to output CSV")
    parser.add_argument("--report", default="output/report.png", help="Path to save protocol pie chart")
    parser.add_argument("--tagged", default="output/extracted_tagged.csv", help="Path to save tagged CSV")

    args = parser.parse_args()

    # Step 1: Extract PCAP features
    print("[*] Parsing PCAP...")
    parse_pcap(args.pcap, args.out)

    # Step 2: Load Suricata alerts and tag malicious flows
    if args.suricata and os.path.exists(args.suricata):
        print("[*] Parsing Suricata alerts...")
        alerts = load_suricata_alerts(args.suricata)
        tag_csv_with_alerts(args.out, alerts, args.tagged)
    else:
        print("[!] Skipping Suricata tagging (no log provided)")

    # Step 3: Generate visualization
    print("[*] Generating protocol pie chart...")
    generate_protocol_pie(args.out, args.report)

if __name__ == "__main__":
    main()
