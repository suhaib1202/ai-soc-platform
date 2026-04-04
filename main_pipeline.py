"""
main_pipeline.py
Master orchestration — runs the entire SOC platform pipeline.
One command to go from zero to fully enriched alerts and dashboard.
"""

import os
import sys
import time
import subprocess
from datetime import datetime

BANNER = """
╔══════════════════════════════════════════════════════════╗
║       AI-POWERED SOC ANALYST ASSISTANT  v1.0            ║
║       Full-Stack Threat Detection Platform               ║
╠══════════════════════════════════════════════════════════╣
║  Detection : Isolation Forest + Random Forest + LSTM    ║
║  Intel     : VirusTotal + AbuseIPDB                     ║
║  Alerting  : Discord                                    ║
║  Dashboard : Streamlit  → http://localhost:8501         ║
╚══════════════════════════════════════════════════════════╝
"""

STAGES = [
    ("generate_logs.py",           "Log Generation (52,000 events)",      True),
    ("ensemble_detect.py",         "Ensemble ML Detection (IF + RF)",      True),
    ("lstm_detect.py",             "LSTM Time-Series Detection",            False),
    ("classify_mitre.py",          "MITRE ATT&CK Classification",           True),
    ("generate_alerts.py",         "Alert Generation & Scoring",            True),
    ("enrich_iocs.py",             "Live Threat Intel (VT + AbuseIPDB)",    False),
    ("alert_dispatcher.py",        "Discord Real-Time Alerts",              False),
    ("index_to_elk.py",            "Elasticsearch Indexing",                False),
    ("generate_navigator_layer.py","MITRE Navigator Layer",                 False),
]


def run_stage(script, name, required):
    print(f"\n{'─'*60}")
    print(f"  ▶  {name}")
    print(f"{'─'*60}\n")

    start  = time.time()
    result = subprocess.run([sys.executable, script])
    secs   = round(time.time() - start, 1)

    if result.returncode == 0:
        print(f"\n  ✅  {name}  ({secs}s)")
        return True
    else:
        print(f"\n  ❌  {name} FAILED")
        if required:
            print("  Fix the error above, then re-run.")
            sys.exit(1)
        return False


def main():
    print(BANNER)
    started = datetime.now()
    print(f"  Started: {started.strftime('%Y-%m-%d %H:%M:%S')}\n")

    done = 0
    for script, name, required in STAGES:
        if os.path.exists(script):
            if run_stage(script, name, required):
                done += 1
        else:
            print(f"\n  [SKIP] {script} not found")

    total_secs = int((datetime.now() - started).total_seconds())

    print(f"""
╔══════════════════════════════════════════════════════════╗
║             PIPELINE COMPLETE ✅                         ║
╠══════════════════════════════════════════════════════════╣
║  Stages completed : {done}/{len(STAGES)}
║  Total time       : {total_secs}s (~{total_secs//60} min)
╠══════════════════════════════════════════════════════════╣
║  Output files:                                          ║
║    data/enriched_alerts.json  ← Main output             ║
║    data/lstm_anomalies.json                             ║
║    data/navigator_layer.json                            ║
║    models/  (3 trained models)                          ║
╠══════════════════════════════════════════════════════════╣
║  Next:  streamlit run app.py                            ║
║  URL:   http://localhost:8501                           ║
╚══════════════════════════════════════════════════════════╝
""")

    answer = input("  Launch dashboard now? (y/n): ").strip().lower()
    if answer == "y":
        print("\n  Starting Streamlit...")
        os.system("streamlit run app.py")


if __name__ == "__main__":
    main()