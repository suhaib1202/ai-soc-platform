"""
alert_dispatcher.py
Real-time Discord alerting for CRITICAL and HIGH severity threats.
"""

import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL")


def send_discord_alert(alert):
    if not DISCORD_WEBHOOK or "discord.com" not in str(DISCORD_WEBHOOK):
        print("  [Discord] Webhook not set in .env — skipping.")
        return False

    severity  = alert.get("severity",  "UNKNOWN")
    ip        = alert.get("source_ip", "N/A")
    hostname  = alert.get("hostname",  "N/A")
    technique = alert.get("technique_id",   "N/A")
    tactic    = alert.get("mitre_tactic",   "N/A")
    score     = alert.get("composite_threat_score",
                           alert.get("threat_score", 0))
    vt        = alert.get("vt_verdict",    "NOT CHECKED")
    abuse     = alert.get("abuse_verdict", "NOT CHECKED")
    triple    = bool(alert.get("triple_confirmed", 0))

    # Discord embed color (decimal)
    color = 16711782 if severity == "CRITICAL" else 16744192

    emoji  = {"CRITICAL":"🚨","HIGH":"🔴","MEDIUM":"🟡","LOW":"🟢"}.get(severity,"⚪")
    action = (
        "**IMMEDIATE ISOLATION REQUIRED.** Block source IP at perimeter. Escalate to Tier 2 now."
        if severity == "CRITICAL"
        else "Investigate host activity. Review authentication logs and network connections."
    )

    payload = {
        "username"  : "SOC Alert Bot",
        "embeds": [{
            "title"      : f"{emoji}  {severity} THREAT DETECTED",
            "color"      : color,
            "description": f"ML ensemble flagged a **{severity}** severity event.",
            "fields": [
                {"name": "Source IP",        "value": f"`{ip}`",       "inline": True},
                {"name": "Hostname",         "value": f"`{hostname}`", "inline": True},
                {"name": "MITRE Technique",  "value": f"`{technique}`","inline": True},
                {"name": "MITRE Tactic",     "value": f"`{tactic}`",   "inline": True},
                {"name": "Composite Score",  "value": f"`{score}/100`","inline": True},
                {"name": "Triple Confirmed", "value": "✅ YES" if triple else "❌ No",
                 "inline": True},
                {"name": "VirusTotal",       "value": str(vt),         "inline": True},
                {"name": "AbuseIPDB",        "value": str(abuse),      "inline": True},
                {"name": "Recommended Action","value": action,          "inline": False},
            ],
            "footer": {
                "text": f"AI SOC Platform  •  {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"
            }
        }]
    }

    try:
        resp = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        if resp.status_code in [200, 204]:
            print(f"  [Discord] ✅ Sent: {ip} ({severity}) Score: {score}")
            return True
        else:
            print(f"  [Discord] ❌ HTTP {resp.status_code}: {resp.text}")
            return False
    except Exception as e:
        print(f"  [Discord] ❌ Error: {e}")
        return False


def dispatch_alerts(
    alerts_path = "data/enriched_alerts.json",
    max_alerts  = 5
):
    print("\n" + "=" * 60)
    print("  DISCORD ALERT DISPATCHER")
    print("=" * 60)

    if not os.path.exists(alerts_path):
        alerts_path = "data/alerts.json"

    alerts = []
    with open(alerts_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    priority = [a for a in alerts if a.get("severity") in ["CRITICAL","HIGH"]]
    priority.sort(
        key=lambda x: x.get("composite_threat_score",
                              x.get("threat_score", 0)),
        reverse=True
    )

    send_count = min(max_alerts, len(priority))
    print(f"\n[+] Total alerts       : {len(alerts):,}")
    print(f"[+] Priority (C/H)     : {len(priority):,}")
    print(f"[+] Sending top        : {send_count}\n")

    sent = 0
    for alert in priority[:max_alerts]:
        if send_discord_alert(alert):
            sent += 1

    print("\n" + "=" * 60)
    print("  DISPATCH COMPLETE")
    print("=" * 60)
    print(f"  Discord alerts sent  : {sent}/{send_count}")
    print("  Check your Discord server now.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    dispatch_alerts()