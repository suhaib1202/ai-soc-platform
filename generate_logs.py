"""
generate_logs.py
Generates 52,000 realistic security events from simulated
Windows and Linux host environments.
Includes normal activity + embedded attack patterns.
"""

import json
import random
import os
from datetime import datetime, timedelta

random.seed(42)

# ── Configuration ─────────────────────────────────────────────────────────────

TOTAL_EVENTS = 52000
ANOMALY_RATE = 0.10   # 10% of events are malicious

# Simulated hostnames
HOSTNAMES = [
    "WIN-BYDT4K2", "WIN-DZTG9P1", "WIN-QRST7M3", "WIN-XYZB5N8",
    "WIN-LMNO2V6", "LINUX-SVR01", "LINUX-SVR02", "LINUX-SVR03",
    "LINUX-WEB01", "LINUX-DB01"
]

# Simulated users
USERS = [
    "admin", "jsmith", "mwilson", "kpatel", "agarcia",
    "root", "svc_backup", "svc_monitor", "guest", "testuser"
]

# Normal source IPs
NORMAL_IPS = [f"192.168.{random.randint(0,5)}.{random.randint(1,254)}"
              for _ in range(50)]

# Known malicious IPs (IOCs)
MALICIOUS_IPS = [
    "185.220.101.34",  # Tor exit node
    "198.20.69.74",    # Shodan scanner
    "89.248.167.131",  # Known C2
    "45.142.212.100",  # Botnet
    "91.92.109.196",   # Malware distribution
    "193.32.162.50",   # Brute force source
    "194.165.16.11",   # Phishing origin
    "23.160.193.145",  # Ransomware C2
]

# Log event types
EVENT_TYPES = [
    "authentication", "network_connection", "process_execution",
    "file_access", "registry_modification", "dns_query",
    "service_control", "scheduled_task"
]

# Attack patterns (embedded in anomalous events)
ATTACK_PATTERNS = [
    {"type": "brute_force",        "failed_attempts": random.randint(50, 200), "bytes": random.randint(100, 500)},
    {"type": "lateral_movement",   "failed_attempts": random.randint(5, 20),   "bytes": random.randint(5000, 50000)},
    {"type": "data_exfiltration",  "failed_attempts": 0,                       "bytes": random.randint(500000, 5000000)},
    {"type": "privilege_escalation","failed_attempts": random.randint(1, 10),  "bytes": random.randint(1000, 10000)},
    {"type": "c2_communication",   "failed_attempts": 0,                       "bytes": random.randint(200, 2000)},
    {"type": "malware_execution",  "failed_attempts": 0,                       "bytes": random.randint(50000, 500000)},
]

# Ports
NORMAL_PORTS  = [80, 443, 22, 3389, 445, 139, 8080, 8443]
SUSPECT_PORTS = [4444, 1337, 31337, 6666, 9999, 8888, 12345]


def random_timestamp(days_back=7):
    """Generate a random timestamp within the last N days."""
    now   = datetime.now()
    delta = timedelta(
        days   = random.randint(0, days_back),
        hours  = random.randint(0, 23),
        minutes= random.randint(0, 59),
        seconds= random.randint(0, 59)
    )
    return (now - delta).isoformat()


def generate_normal_event():
    """Generate a normal (benign) security log event."""
    return {
        "generated_at"      : random_timestamp(),
        "hostname"          : random.choice(HOSTNAMES),
        "username"          : random.choice(USERS),
        "source_ip"         : random.choice(NORMAL_IPS),
        "event_type"        : random.choice(EVENT_TYPES),
        "port"              : random.choice(NORMAL_PORTS),
        "bytes_transferred" : random.randint(100, 50000),
        "failed_attempts"   : random.randint(0, 3),
        "process_count"     : random.randint(1, 20),
        "connection_count"  : random.randint(1, 50),
        "ioc_flag"          : 0,
        "is_anomaly"        : 0,
        "severity"          : "LOW",
        "threat_score"      : round(random.uniform(0, 20), 2),
        "os_type"           : "Windows" if "WIN" in random.choice(HOSTNAMES) else "Linux",
        "file_hash"         : ""
    }


def generate_attack_event():
    """Generate a malicious security log event."""
    pattern  = random.choice(ATTACK_PATTERNS)
    mal_ip   = random.choice(MALICIOUS_IPS)
    hostname = random.choice(HOSTNAMES)
    hour     = random.choice([0, 1, 2, 3, 22, 23])  # After hours

    ts_now   = datetime.now()
    ts_delta = timedelta(
        days    = random.randint(0, 7),
        hours   = hour,
        minutes = random.randint(0, 59),
        seconds = random.randint(0, 59)
    )
    timestamp = (ts_now - ts_delta).isoformat()

    severity    = random.choice(["HIGH", "CRITICAL"])
    threat_score = round(random.uniform(65, 100), 2)

    return {
        "generated_at"      : timestamp,
        "hostname"          : hostname,
        "username"          : random.choice(["admin", "root", "svc_backup", "guest"]),
        "source_ip"         : mal_ip,
        "event_type"        : pattern["type"],
        "port"              : random.choice(SUSPECT_PORTS),
        "bytes_transferred" : pattern["bytes"],
        "failed_attempts"   : pattern["failed_attempts"],
        "process_count"     : random.randint(10, 80),
        "connection_count"  : random.randint(50, 500),
        "ioc_flag"          : 1,
        "is_anomaly"        : 1,
        "severity"          : severity,
        "threat_score"      : threat_score,
        "os_type"           : "Windows" if "WIN" in hostname else "Linux",
        "file_hash"         : "".join(random.choices("0123456789abcdef", k=64))
    }


def generate_logs(output_path="data/raw_logs.json"):
    """Generate TOTAL_EVENTS log events and save as NDJSON."""
    print("\n" + "=" * 60)
    print("  LOG GENERATION")
    print("=" * 60)

    os.makedirs("data", exist_ok=True)

    n_anomalies = int(TOTAL_EVENTS * ANOMALY_RATE)
    n_normal    = TOTAL_EVENTS - n_anomalies

    print(f"\n[+] Total events   : {TOTAL_EVENTS:,}")
    print(f"[+] Normal events  : {n_normal:,}")
    print(f"[+] Attack events  : {n_anomalies:,} ({ANOMALY_RATE*100:.0f}%)")

    events = []
    for _ in range(n_normal):
        events.append(generate_normal_event())
    for _ in range(n_anomalies):
        events.append(generate_attack_event())

    random.shuffle(events)

    with open(output_path, "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    print(f"\n[+] Saved to       : {output_path}")
    print(f"[+] File size      : {os.path.getsize(output_path) / 1024 / 1024:.1f} MB")

    # Quick summary
    ips = set(e["source_ip"] for e in events if e["ioc_flag"] == 1)
    print(f"\n  Attack types     : {len(ATTACK_PATTERNS)}")
    print(f"  Malicious IPs    : {len(ips)}")
    print(f"  Hosts simulated  : {len(HOSTNAMES)}")

    print("\n" + "=" * 60)
    print("  LOG GENERATION COMPLETE")
    print("=" * 60 + "\n")

    return events


if __name__ == "__main__":
    generate_logs()