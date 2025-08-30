# import os
# import json
# import re
# from collections import defaultdict
# from Backend.main import extract_iocs

# LOGS_FILE = os.path.join(os.getcwd(), "all_logs.json")
# MITRE_FILE = "mitre_data/enterprise-attack.json"
# OUTPUT_FILE = os.path.join(os.getcwd(), "classified_logs.json")

# # Load logs
# with open(LOGS_FILE, "r", encoding="utf-8") as f:
#     all_logs = json.load(f)

# # Load MITRE ATT&CK JSON
# with open(MITRE_FILE, "r", encoding="utf-8") as f:
#     mitre_data = json.load(f)

# # Build searchable technique keyword index
# techniques = {}
# for obj in mitre_data["objects"]:
#     if obj["type"] == "attack-pattern":
#         tid = next((ref["external_id"] for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"), None)
#         name = obj.get("name", "")
#         desc = obj.get("description", "")
#         search_blob = f"{name} {desc}".lower()
#         keywords = set(re.findall(r"[a-z0-9]+", search_blob))  # tokenize
#         techniques[(tid, name)] = keywords

# classified_logs = []

# for log in all_logs:
#     text = str(log.get("text", "")).lower()
#     tokens = set(re.findall(r"[a-z0-9]+", text))

#     matched = []
#     for (tid, tech_name), keywords in techniques.items():
#         if tokens & keywords:  # intersection not empty
#             matched.append({"id": tid, "name": tech_name})

#     classified_logs.append({
#         "filename": log.get("filename"),
#         "text": log.get("text"),
#         "matched": matched,
#         "iocs": extract_iocs(log.get("text", "")),
#         "file_risk_score": len(matched) * 1.5 + len(extract_iocs(log.get("text", ""))) * 0.5
#     })

# # Save output
# with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
#     json.dump(classified_logs, f, indent=2)

# print(f"Classified {len(classified_logs)} logs. Results saved to {OUTPUT_FILE}")

import os, json

LOGS_FILE = os.path.join(os.getcwd(), "all_logs.json")
OUTPUT_FILE = os.path.join(os.getcwd(), "classified_logs.json")

# Simple event-to-technique mapping
EVENT_TO_TECH = {
    4624: {"id": "T1078", "name": "Valid Accounts"},  # login
    4688: {"id": "T1059", "name": "Command and Scripting Interpreter"},  # process creation
}

SUSPICIOUS_PROCS = {
    "powershell": {"id": "T1059.001", "name": "PowerShell"},
    "rundll32.exe": {"id": "T1218.011", "name": "Signed Binary Proxy Execution: Rundll32"},
    "lsass.exe": {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory"},
    "wmic.exe": {"id": "T1047", "name": "Windows Management Instrumentation"},
    "certutil.exe": {"id": "T1105", "name": "Ingress Tool Transfer"},
    "mshta.exe": {"id": "T1218.005", "name": "Mshta"}
}

classified_logs = []

with open(LOGS_FILE, "r", encoding="utf-8") as f:
    logs = json.load(f)

for log in logs:
    matched = []
    text = json.dumps(log).lower()

    # Match EventID
    eid = log.get("EventID")
    if eid in EVENT_TO_TECH:
        matched.append(EVENT_TO_TECH[eid])

    # Match process names
    for proc, tech in SUSPICIOUS_PROCS.items():
        if proc in text:
            matched.append(tech)

    classified_logs.append({
        "filename": log.get("filename", "unknown"),
        "matched": matched,
        "text": text[:200]
    })

# Save
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(classified_logs, f, indent=2)

print(f"✅ Classified {len(classified_logs)} logs")
print(f"🔍 Matches found in {sum(1 for x in classified_logs if x['matched'])} logs")