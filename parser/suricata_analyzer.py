
import json
import os

def load_suricata_alerts(eve_json_path):
    alerts = []
    if not os.path.exists(eve_json_path):
        print(f"[-] Suricata log not found: {eve_json_path}")
        return alerts

    with open(eve_json_path, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
                if entry.get("event_type") == "alert":
                    alert = {
                        "timestamp": entry.get("timestamp"),
                        "src_ip": entry.get("src_ip"),
                        "dest_ip": entry.get("dest_ip"),
                        "alert_msg": entry.get("alert", {}).get("signature"),
                        "severity": entry.get("alert", {}).get("severity")
                    }
                    alerts.append(alert)
            except json.JSONDecodeError:
                continue

    print(f"[+] Loaded {len(alerts)} alerts from Suricata log.")
    return alerts
