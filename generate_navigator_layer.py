"""
generate_navigator_layer.py
Generates a MITRE ATT&CK Navigator layer from detected techniques.
Upload the output JSON to https://mitre-attack.github.io/attack-navigator/
"""

import json
import os
import pandas as pd


def generate_layer(
    classified_path = "data/classified_anomalies.json",
    output_path     = "data/navigator_layer.json"
):
    print("\n" + "=" * 60)
    print("  MITRE ATT&CK NAVIGATOR LAYER")
    print("=" * 60)

    df = pd.read_json(classified_path, lines=True)
    print(f"\n[+] Events loaded : {len(df):,}")

    # Count detections per technique
    counts = {}
    if "technique_id" in df.columns:
        counts = df["technique_id"].value_counts().to_dict()

    if not counts:
        print("[!] No technique_id column found. Check classify_mitre.py ran correctly.")
        return

    max_count = max(counts.values()) if counts else 1

    # Build navigator layer
    techniques = []
    for tid, count in counts.items():
        score = round((count / max_count) * 100)
        techniques.append({
            "techniqueID" : tid,
            "score"       : score,
            "comment"     : f"Detected {count} times",
            "enabled"     : True,
            "showSubtechniques": False
        })

    layer = {
        "name"        : "AI SOC Platform — Detected Techniques",
        "version"     : "4.5",
        "domain"      : "enterprise-attack",
        "description" : "MITRE ATT&CK coverage from AI anomaly detection pipeline",
        "gradient"    : {
            "colors" : ["#ffffff","#ff8c00","#ff3366"],
            "minValue": 0,
            "maxValue": 100
        },
        "techniques"  : techniques
    }

    os.makedirs("data", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(layer, f, indent=2)

    print(f"\n  Techniques in layer : {len(techniques)}")
    for t in sorted(techniques, key=lambda x: -x["score"])[:5]:
        print(f"    {t['techniqueID']}  score={t['score']}  {t['comment']}")

    print(f"\n  Layer saved to      : {output_path}")
    print(f"\n  NEXT STEPS:")
    print(f"  1. Go to: https://mitre-attack.github.io/attack-navigator/")
    print(f"  2. Click 'Open Existing Layer' → 'Upload from local'")
    print(f"  3. Select: {output_path}")
    print(f"  4. Screenshot the colored heatmap for your portfolio")
    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    generate_layer()