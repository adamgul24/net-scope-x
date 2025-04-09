
import pandas as pd
import matplotlib.pyplot as plt

def generate_protocol_pie(csv_path, out_path):
    df = pd.read_csv(csv_path)
    if "Protocol" not in df.columns:
        print("[-] CSV missing 'Protocol' column.")
        return

    protocol_counts = df["Protocol"].value_counts()
    plt.figure(figsize=(8,6))
    protocol_counts.plot.pie(autopct='%1.1f%%', startangle=140, shadow=True)
    plt.title("Protocol Distribution")
    plt.ylabel("")
    plt.tight_layout()
    plt.savefig(out_path)
    print(f"[+] Saved pie chart to {out_path}")

def generate_source_ip_bar(csv_path, out_path="output/source_ip_bar.png"):
    df = pd.read_csv(csv_path)
    if "Src_IP" not in df.columns:
        print("[-] CSV missing 'Src_IP' column.")
        return

    src_counts = df["Src_IP"].value_counts().head(10)
    plt.figure(figsize=(10,6))
    src_counts.plot(kind='bar', color='skyblue')
    plt.title("Top 10 Source IPs")
    plt.xlabel("Source IP")
    plt.ylabel("Packet Count")
    plt.tight_layout()
    plt.savefig(out_path)
    print(f"[+] Saved source IP bar chart to {out_path}")

def generate_time_series(csv_path, out_path="output/traffic_over_time.png"):
    df = pd.read_csv(csv_path)
    if "Timestamp" not in df.columns:
        print("[-] CSV missing 'Timestamp' column.")
        return

    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    df = df.dropna(subset=['Timestamp'])
    df.set_index('Timestamp', inplace=True)
    time_series = df.resample('1Min').size()

    plt.figure(figsize=(10,6))
    time_series.plot(kind='line', color='darkred')
    plt.title("Traffic Volume Over Time")
    plt.xlabel("Time")
    plt.ylabel("Packet Count")
    plt.tight_layout()
    plt.savefig(out_path)
    print(f"[+] Saved time-series chart to {out_path}")
