# 🛰️ NetScope 

> **Advanced Network Traffic Analyzer + Threat Classifier**  
> Powered by Python, Suricata, PyShark, and Flask

**NetScope** gives you deep insight into packet-level traffic.  
Parse `.pcap` files, tag malicious patterns with Suricata alerts, visualize activity, and export machine-learning-ready data — via both CLI and a sleek Flask dashboard.

---

## 🔍 Features

### 📦 PCAP + Suricata Analysis
- Parse `.pcap` traffic with PyShark
- Extract protocol, timestamp, IPs, size, summaries
- Match alerts from `eve.json` generated by **Suricata**
- Automatically tag flows as `benign` or `malicious`

### 📊 Visual Analytics
- Protocol distribution pie chart
- Top 10 source IP bar chart
- Timeline of packet flow

### 💾 Data Export
- Clean CSV output for each PCAP
- Optional tagged CSV with alerts
- ML-compatible fields for supervised training

### 🌐 Web Dashboard (Flask)
- Upload PCAPs + `eve.json`
- See visual results and download CSV
- Fast, simple interface for forensics, students, red teams

---

## 🧰 Tech Stack

| Layer        | Tools Used                             |
|--------------|-----------------------------------------|
| PCAP Parsing | `pyshark`                               |
| Alert Correlation | `Suricata (eve.json)`              |
| Visuals      | `matplotlib`, `pandas`                  |
| Backend CLI  | `argparse`, `pandas`, `csv`             |
| Web UI       | `Flask`, HTML templating                |
| Rules Engine | `suricata.rules`                        |

---

## 📂 Folder Layout

```bash
net-scope/
├── main.py                  # CLI analyzer
├── app.py                   # Flask web dashboard
├── parser/
│   ├── pcap_reader.py       # PyShark parser
│   └── suricata_analyzer.py # JSON alert correlation
├── visualizer/
│   └── traffic_plot.py      # Pie, bar, and time series graphs
├── templates/               # Web UI templates
│   ├── index.html
│   └── results.html
├── rules/
│   └── suricata.rules       # Example ruleset
├── output/                  # Generated charts + CSVs
├── requirements.txt
├── README.md

📦 Install Requirements
pip install -r requirements.txt

🧪 Run CLI
python main.py --pcap test_pcaps/sample.pcap --suricata test_pcaps/eve.json
Output CSVs and visual reports are saved to /output/

🌍 Run Web UI
python app.py

Then visit:
🌐 http://localhost:8080

🧾 License
MIT — Made for research, red teamers, blue teamers, and educators.
Use it to learn, simulate, and defend.

