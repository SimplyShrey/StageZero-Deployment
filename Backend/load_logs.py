import os
import json
import pandas as pd
import glob
import chardet
import ibm_boto3
from ibm_botocore.client import Config

LOGS_DIR = "logs"  # path to your logs folder
OUTPUT_FILE = os.path.join(os.getcwd(), "all_logs.json")

all_logs = []
output_path = os.path.join(os.getcwd(), "all_logs.json")

def read_file(file_path):
    """Try multiple encodings to read a file."""
    encodings = ["utf-8", "utf-16", "utf-32", "latin1", "utf-8-sig"]
    for enc in encodings:
        try:
            with open(file_path, "r", encoding=enc) as f:
                return f.read()
        except Exception:
            continue
    print(f"Failed to read {file_path}")
    return None
def read_csv_file(file_path):
    for enc in ("utf-8", "utf-16", "utf-32", "latin1"):
        try:
            df = pd.read_csv(file_path, encoding=enc, on_bad_lines="skip")
            if df.empty:
                return None
            return df
        except Exception:
            continue
    print(f"Failed to read CSV: {file_path}")
    return None

# Walk through all subfolders
for root, dirs, files in os.walk(LOGS_DIR):
    for file in files:
        file_path = os.path.join(root, file)
        try:
            if file.endswith((".txt", ".log")):
                text = read_file(file_path)
                if text:
                    all_logs.append({"filename": file_path, "text": text})

            elif file.endswith(".csv"):
                df = read_csv_file(file_path)
                if df is None:
                    continue
                for _, row in df.iterrows():
                    if "text" in row:
                        all_logs.append({"filename": file_path, "text": str(row["text"])})

            elif file.endswith(".json"):
                text = read_file(file_path)
                if text:
                    try:
                        data = json.loads(text)
                        if isinstance(data, list):
                            for entry in data:
                                all_logs.append({"filename": file_path, "text": str(entry)})
                        elif isinstance(data, dict):
                            all_logs.append({"filename": file_path, "text": str(data)})
                    except Exception as e:
                        print(f"JSON parse error {file_path}: {e}")
        except Exception as e:
            print(f"Error reading {file_path}: {e}")

# Save all logs to one JSON file
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(all_logs, f, indent=2)

print(f"Loaded {len(all_logs)} logs into {OUTPUT_FILE}")