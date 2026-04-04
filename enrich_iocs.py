"""
enrich_iocs.py
Live threat intelligence enrichment using VirusTotal + AbuseIPDB.
Validates every flagged IP against global threat databases in real time.
"""

import os
import time
import json
import requests
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

VT_KEY    = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")


def check_virustotal(ip):
    """Check IP reputation on VirusTotal. Free: 4 requests/minute."""
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_KEY},
            timeout=10
        )
        if resp.status_code == 200:
            attrs = resp.json()["data"]["attributes"]
            stats = attrs["last_analysis_stats"]
            mal   = stats.get("malicious", 0)
            sus   = stats.get("suspicious", 0)
            return {
                "vt_malicious"  : mal,
                "vt_suspicious" : sus,
                "vt_harmless"   : stats.get("harmless", 0),
                "vt_reputation" : attrs.get("reputation", 0),
                "vt_checked"    : True,
                "vt_verdict"    : "MALICIOUS"  if mal > 2 else
                                  "SUSPICIOUS" if sus > 0 else "CLEAN"
            }
        elif resp.status_code == 429:
            print("  [VT] Rate limit — waiting 65s...")
            time.sleep(65)
            return check_virustotal(ip)
        else:
            return {"vt_checked": False, "vt_verdict": "UNKNOWN", "vt_malicious": 0}
    except Exception as e:
        return {"vt_checked": False, "vt_verdict": "ERROR", "vt_malicious": 0}


def check_abuseipdb(ip):
    """Check IP abuse score on AbuseIPDB. Free: 1000 requests/day."""
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        if resp.status_code == 200:
            data  = resp.json()["data"]
            score = data.get("abuseConfidenceScore", 0)
            return {
                "abuse_score"   : score,
                "abuse_reports" : data.get("totalReports", 0),
                "abuse_country" : data.get("countryCode", "??"),
                "abuse_isp"     : data.get("isp", "Unknown"),
                "abuse_checked" : True,
                "abuse_verdict" : "HIGH_RISK"   if score > 75 else
                                  "MEDIUM_RISK" if score > 25 else "LOW_RISK"
            }
        elif resp.status_code == 429:
            return {"abuse_checked": False, "abuse_score": 0,
                    "abuse_verdict": "DAILY_LIMIT"}
        else:
            return {"abuse_checked": False, "abuse_score": 0, "abuse_verdict": "UNKNOWN"}
    except Exception:
        return {"abuse_checked": False, "abuse_score": 0, "abuse_verdict": "ERROR"}


def composite_score(alert, vt, abuse):
    base    = float(alert.get("threat_score", 0))
    vt_add  = min(vt.get("vt_malicious", 0) * 5, 30)
    ab_add  = (abuse.get("abuse_score", 0) / 100) * 25
    rep_pen = max(-vt.get("vt_reputation", 0) * 2, 0)
    return round(min(base + vt_add + ab_add + rep_pen, 100), 2)


def enrich_alerts(
    alerts_path = "data/alerts.json",
    output_path = "data/enriched_alerts.json"
):
    print("\n" + "=" * 60)
    print("  THREAT INTELLIGENCE ENRICHMENT")
    print("  VirusTotal  +  AbuseIPDB")
    print("=" * 60)

    alerts = []
    with open(alerts_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    priority = [a for a in alerts if a.get("severity") in ["CRITICAL","HIGH"]][:20]
    others   = [a for a in alerts if a.get("severity") not in ["CRITICAL","HIGH"]]

    print(f"\n[+] Total alerts       : {len(alerts):,}")
    print(f"[+] Priority (C/H)     : {len(priority):,}  <- enriching these")
    print(f"[+] Others (M/L)       : {len(others):,}  <- ML score only\n")

    enriched      = []
    req_count     = 0
    window_start  = time.time()

    for i, alert in enumerate(priority):
        ip = alert.get("source_ip", "")
        print(f"  [{i+1}/{len(priority)}] {ip}")

        vt    = check_virustotal(ip) if ip else {}
        req_count += 1

        # Free tier: 4 VT requests per 60 seconds
        if req_count % 4 == 0:
            elapsed = time.time() - window_start
            if elapsed < 62:
                wait = 62 - elapsed
                print(f"\n  [Rate Limit] Pausing {wait:.0f}s...\n")
                time.sleep(wait)
            window_start = time.time()

        abuse = check_abuseipdb(ip) if ip else {}
        comp  = composite_score(alert, vt, abuse)

        print(f"    VT       : {vt.get('vt_verdict','N/A')} | "
              f"Malicious: {vt.get('vt_malicious', 0)}")
        print(f"    AbuseIPDB: {abuse.get('abuse_verdict','N/A')} | "
              f"Score: {abuse.get('abuse_score', 0)}/100")
        print(f"    Composite: {comp}/100")

        enriched.append({
            **alert, **vt, **abuse,
            "composite_threat_score": comp,
            "enriched_at": datetime.now().isoformat(),
            "enrichment_source": "VirusTotal+AbuseIPDB"
        })

    for alert in others:
        enriched.append({
            **alert,
            "composite_threat_score": float(alert.get("threat_score", 0)),
            "enriched_at": datetime.now().isoformat(),
            "enrichment_source": "ML_only"
        })

    with open(output_path, "w") as f:
        for a in enriched:
            f.write(json.dumps(a, default=str) + "\n")

    malicious = sum(1 for a in enriched if a.get("vt_verdict") == "MALICIOUS")
    high_risk = sum(1 for a in enriched if a.get("abuse_verdict") == "HIGH_RISK")
    avg_score = sum(a.get("composite_threat_score", 0) for a in enriched) / max(len(enriched), 1)

    print("\n" + "=" * 60)
    print("  ENRICHMENT COMPLETE")
    print("=" * 60)
    print(f"  Total enriched     : {len(enriched):,}")
    print(f"  VT Malicious       : {malicious}")
    print(f"  AbuseIPDB High Risk: {high_risk}")
    print(f"  Avg Composite Score: {avg_score:.1f}/100")
    print(f"  Output             : {output_path}")
    print("=" * 60 + "\n")
    return enriched


if __name__ == "__main__":
    enrich_alerts()