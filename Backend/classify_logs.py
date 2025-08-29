import os
import json

LOGS_FILE = os.path.join(os.getcwd(), "all_logs.json")
MITRE_FILE = "mitre_data/enterprise-attack.json"
OUTPUT_FILE = os.path.join(os.getcwd(), "classified_logs.json")

# Load logs
with open(LOGS_FILE, "r", encoding="utf-8") as f:
    all_logs = json.load(f)

# Load MITRE ATT&CK JSON
with open(MITRE_FILE, "r", encoding="utf-8") as f:
    mitre_data = json.load(f)


techniques = {}
for obj in mitre_data["objects"]:
    if obj["type"] == "attack-pattern":
        name = obj.get("name", "")
        keywords = [word.lower() for word in name.split()]
        techniques[name] = set(keywords)

classified_logs = []

# Classify logs
for log in all_logs:
    text = log["text"].lower()
    matched_techniques = []
    for tech_name, keywords in techniques.items():
        if any(word in text for word in keywords):
            matched_techniques.append(tech_name)
    classified_logs.append({
        "filename": log["filename"],
        "text": log["text"],
        "matched_techniques": matched_techniques
    })

# Save output
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(classified_logs, f, indent=2)

print(f"Classified {len(classified_logs)} logs. Results saved to {OUTPUT_FILE}")
