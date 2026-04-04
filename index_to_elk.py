"""
index_to_elk.py
Index enriched alerts into Elasticsearch for Kibana visualization.
"""

import json
import os
from elasticsearch import Elasticsearch
from datetime import datetime

ES_HOST  = "http://localhost:9200"
ES_INDEX = "soc-alerts"


def index_alerts(alerts_path="data/alerts.json"):
    print("\n" + "=" * 60)
    print("  ELASTICSEARCH INDEXING")
    print(f"  Index: {ES_INDEX}")
    print("=" * 60)

    try:
        es = Elasticsearch([ES_HOST])
        if not es.ping():
            print("[!] Elasticsearch not reachable.")
            print("[!] Run: docker-compose up -d  and wait 60 seconds.")
            return
        print(f"\n[+] Connected to Elasticsearch at {ES_HOST}")
    except Exception as e:
        print(f"[!] Connection error: {e}")
        return

    # Delete old index if it exists
    if es.indices.exists(index=ES_INDEX):
        es.indices.delete(index=ES_INDEX)
        print(f"[+] Deleted old index: {ES_INDEX}")

    # Create index with timestamp mapping
    es.indices.create(index=ES_INDEX, mappings={
        "properties": {
            "generated_at": {"type": "date"},
            "alert_generated_at": {"type": "date"},
            "enriched_at": {"type": "date"}
        }
    })
    print(f"[+] Created index: {ES_INDEX}")

    # Load and index alerts
    alerts = []
    with open(alerts_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    print(f"[+] Indexing {len(alerts):,} documents...")

    success, failed = 0, 0
    for i, alert in enumerate(alerts):
        try:
            es.index(index=ES_INDEX, document=alert, id=str(i))
            success += 1
        except Exception:
            failed += 1

        if (i + 1) % 500 == 0:
            print(f"  Indexed {i+1:,}/{len(alerts):,}...")

    print("\n" + "=" * 60)
    print("  INDEXING COMPLETE")
    print("=" * 60)
    print(f"  Successfully indexed : {success:,}")
    print(f"  Failed               : {failed}")
    print(f"\n  Now open Kibana: http://localhost:5601")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    index_alerts()