"""
classify_mitre.py
Maps detected anomalies to MITRE ATT&CK techniques.
Covers 14 techniques across 6 tactics.
"""

import os
import json
import pandas as pd
from datetime import datetime

# ── MITRE ATT&CK Registry ─────────────────────────────────────────────────────

MITRE_REGISTRY = {
    "T1110": {"name": "Brute Force",              "tactic": "Credential Access",   "keywords": ["brute_force","failed_attempts","authentication"]},
    "T1078": {"name": "Valid Accounts",           "tactic": "Initial Access",       "keywords": ["authentication","login","svc_"]},
    "T1021": {"name": "Remote Services",          "tactic": "Lateral Movement",     "keywords": ["lateral_movement","rdp","smb","ssh","3389","445","22"]},
    "T1570": {"name": "Lateral Tool Transfer",    "tactic": "Lateral Movement",     "keywords": ["lateral_movement","file_access","smb"]},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation","keywords": ["privilege_escalation","escalation","exploit"]},
    "T1055": {"name": "Process Injection",        "tactic": "Privilege Escalation", "keywords": ["privilege_escalation","process_execution","injection"]},
    "T1134": {"name": "Access Token Manipulation","tactic": "Privilege Escalation", "keywords": ["privilege_escalation","token","impersonation"]},
    "T1071": {"name": "Application Layer Protocol","tactic": "Command & Control",   "keywords": ["c2_communication","dns_query","http","443","80"]},
    "T1105": {"name": "Ingress Tool Transfer",    "tactic": "Command & Control",    "keywords": ["c2_communication","malware_execution","download"]},
    "T1572": {"name": "Protocol Tunneling",       "tactic": "Command & Control",    "keywords": ["c2_communication","tunnel","4444","1337"]},
    "T1041": {"name": "Exfiltration Over C2",     "tactic": "Exfiltration",         "keywords": ["data_exfiltration","large_transfer","bytes"]},
    "T1048": {"name": "Exfiltration Over Alt Protocol","tactic": "Exfiltration",    "keywords": ["data_exfiltration","dns","ftp"]},
    "T1059": {"name": "Command Interpreter",      "tactic": "Execution",            "keywords": ["malware_execution","process_execution","cmd","powershell","bash"]},
    "T1547": {"name": "Boot/Logon Autostart",     "tactic": "Persistence",          "keywords": ["registry_modification","service_control","scheduled_task"]},
}

DEFAULT_TECHNIQUE = "T1078"   # Valid Accounts — fallback


def classify_event(event):
    """Map a single event to the most appropriate MITRE technique."""
    event_type = str(event.get("event_type", "")).lower()
    username   = str(event.get("username", "")).lower()
    port       = str(event.get("port", ""))

    search_text = f"{event_type} {username} {port}"

    # Score each technique by keyword matches
    best_tid   = DEFAULT_TECHNIQUE
    best_score = 0

    for tid, info in MITRE_REGISTRY.items():
        score = sum(1 for kw in info["keywords"] if kw in search_text)
        if score > best_score:
            best_score = score
            best_tid   = tid

    return best_tid, MITRE_REGISTRY[best_tid]


def run_classify(
    input_path  = "data/lstm_anomalies.json",
    output_path = "data/classified_anomalies.json"
):
    # Fallback if LSTM output doesn't exist
    if not os.path.exists(input_path):
        input_path = "data/ensemble_anomalies.json"

    print("\n" + "=" * 60)
    print("  MITRE ATT&CK CLASSIFICATION")
    print(f"  Input: {input_path}")
    print("=" * 60)

    df = pd.read_json(input_path, lines=True)
    print(f"\n[+] Events to classify : {len(df):,}")

    technique_ids   = []
    technique_names = []
    tactics         = []

    for _, row in df.iterrows():
        tid, info = classify_event(row.to_dict())
        technique_ids.append(tid)
        technique_names.append(info["name"])
        tactics.append(info["tactic"])

    df["technique_id"]   = technique_ids
    df["technique_name"] = technique_names
    df["mitre_tactic"]   = tactics
    df["classified_at"]  = datetime.now().isoformat()

    df.to_json(output_path, orient="records", lines=True, default_handler=str)

    # Summary
    by_technique = df.groupby(["technique_id","technique_name","mitre_tactic"]).size()
    by_technique = by_technique.reset_index(name="count").sort_values("count", ascending=False)

    print(f"\n  {'Technique ID':<10} {'Name':<35} {'Tactic':<25} {'Count'}")
    print(f"  {'-'*85}")
    for _, row in by_technique.iterrows():
        print(f"  {row['technique_id']:<10} {row['technique_name']:<35} "
              f"{row['mitre_tactic']:<25} {row['count']}")

    print("\n" + "=" * 60)
    print("  CLASSIFICATION COMPLETE")
    print("=" * 60)
    print(f"  Total classified   : {len(df):,}")
    print(f"  Unique techniques  : {df['technique_id'].nunique()}")
    print(f"  Output             : {output_path}")
    print("=" * 60 + "\n")
    return df


if __name__ == "__main__":
    run_classify()