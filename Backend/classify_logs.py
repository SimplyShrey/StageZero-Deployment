import os
import json
import re
from collections import defaultdict

# --------------------------
# Paths
# --------------------------
LOGS_FILE = os.path.join(os.getcwd(), "all_logs.json")
MITRE_FILE = os.path.join(os.getcwd(), "mitre_data", "enterprise-attack.json")
OUTPUT_FILE = os.path.join(os.getcwd(), "classified_logs.json")

# --------------------------
# Load MITRE ATT&CK JSON
# --------------------------
with open(MITRE_FILE, "r", encoding="utf-8") as f:
    mitre_bundle = json.load(f)

# Build technique dictionary: id -> name, tactics, and keywords
mitre_techniques = {}
for obj in mitre_bundle.get("objects", []):
    if obj.get("type") == "attack-pattern":
        # tactics
        tactics = []
        if obj.get("kill_chain_phases"):
            tactics = [phase["phase_name"] for phase in obj["kill_chain_phases"]]
        elif obj.get("x_mitre_tactics"):
            tactics = obj["x_mitre_tactics"]

        # keywords: from technique name + optional description
        keywords = [obj["name"].lower()]
        desc = obj.get("description", "")
        if desc:
            # split into words, keep only alphanum longer than 3 chars
            desc_words = re.findall(r"\b[a-z0-9]{4,}\b", desc.lower())
            keywords.extend(desc_words)

        mitre_techniques[obj["id"]] = {
            "name": obj["name"],
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", []),
            "keywords": set(keywords)
        }

print(f"Loaded {len(mitre_techniques)} MITRE techniques.")

# --------------------------
# Load logs
# --------------------------
with open(LOGS_FILE, "r", encoding="utf-8") as f:
    logs = json.load(f)

classified_logs = []

for log in logs:
    matched = []
    text = json.dumps(log).lower()

    # Scan log for any MITRE technique keywords
    for mitre_id, tech in mitre_techniques.items():
        for kw in tech["keywords"]:
            if kw in text:
                matched.append({
                    "id": mitre_id,
                    "name": tech["name"],
                    "tactics": tech["tactics"],
                    "match_type": "keyword",
                    "score": 1
                })
                break  # stop after first keyword match for this technique

    classified_logs.append({
        "filename": log.get("filename", "unknown"),
        "matched": matched,
        "text": text[:200] + ("..." if len(text) > 200 else ""),
        "file_risk_score": len(matched)
    })

# --------------------------
# Save results
# --------------------------
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(classified_logs, f, indent=2)

total_matches = sum(1 for x in classified_logs if x["matched"])
print(f"✅ Classified {len(classified_logs)} logs")
print(f"🔍 Matches found in {total_matches} logs")
