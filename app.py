
from flask import Flask, request, render_template, redirect, url_for, send_file
import os
import uuid
from parser.pcap_reader import parse_pcap
from parser.suricata_analyzer import load_suricata_alerts
from visualizer.traffic_plot import generate_protocol_pie, generate_source_ip_bar, generate_time_series
from main import tag_csv_with_alerts
import shutil

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "output"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        pcap_file = request.files["pcap"]
        suricata_file = request.files.get("suricata")

        session_id = str(uuid.uuid4())
        pcap_path = os.path.join(UPLOAD_FOLDER, f"{session_id}.pcap")
        pcap_file.save(pcap_path)

        csv_path = os.path.join(OUTPUT_FOLDER, f"{session_id}_extracted.csv")
        tagged_csv_path = os.path.join(OUTPUT_FOLDER, f"{session_id}_tagged.csv")
        report_path = os.path.join(OUTPUT_FOLDER, f"{session_id}_report.png")
        srcbar_path = os.path.join(OUTPUT_FOLDER, f"{session_id}_srcbar.png")
        timeseries_path = os.path.join(OUTPUT_FOLDER, f"{session_id}_timeline.png")

        parse_pcap(pcap_path, csv_path)
        if suricata_file:
            suricata_path = os.path.join(UPLOAD_FOLDER, f"{session_id}_eve.json")
            suricata_file.save(suricata_path)
            alerts = load_suricata_alerts(suricata_path)
            tag_csv_with_alerts(csv_path, alerts, tagged_csv_path)

        generate_protocol_pie(csv_path, report_path)
        generate_source_ip_bar(csv_path, srcbar_path)
        generate_time_series(csv_path, timeseries_path)

        return render_template("results.html", 
            report=report_path, 
            srcbar=srcbar_path,
            timeline=timeseries_path,
            csv=tagged_csv_path if suricata_file else csv_path
        )
    return render_template("index.html")

@app.route("/download/<path:filename>")
def download_file(filename):
    return send_file(filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
