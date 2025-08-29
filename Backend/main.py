import os
import json
import pandas as pd
import zipfile
import tempfile
import py7zr
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Allow React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # change if needed
    allow_methods=["*"],
    allow_headers=["*"]
)

MITRE_FILE = "mitre_data/enterprise-attack.json"

# ---------------------- Helpers ----------------------
def read_file(file_path):
    encodings = ["utf-8", "utf-16", "utf-32", "latin1", "utf-8-sig"]
    for enc in encodings:
        try:
            with open(file_path, "r", encoding=enc) as f:
                return f.read()
        except Exception:
            continue
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
    return None

def load_logs_from_folder(main_folder):
    all_logs = []
    for root, dirs, files in os.walk(main_folder):
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
                        except:
                            continue
            except:
                continue
    return all_logs

def classify_logs(all_logs):
    with open(MITRE_FILE, "r", encoding="utf-8") as f:
        mitre_data = json.load(f)

    techniques = {}
    for obj in mitre_data["objects"]:
        if obj["type"] == "attack-pattern":
            name = obj.get("name", "")
            keywords = [word.lower() for word in name.split()]
            techniques[name] = set(keywords)

    classified_logs = []
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
    return classified_logs

# ---------------------- API Endpoints ----------------------
@app.post("/upload-logs")
async def upload_logs(file: UploadFile = File(...)):
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = os.path.join(tmpdir, file.filename)
        with open(file_path, "wb") as f:
            f.write(await file.read())

        extract_path = os.path.join(tmpdir, "extracted")
        os.makedirs(extract_path, exist_ok=True)

        # Extract ZIP or 7z
        if file.filename.endswith(".zip"):
            with zipfile.ZipFile(file_path, "r") as zip_ref:
                zip_ref.extractall(extract_path)
        elif file.filename.endswith(".7z"):
            with py7zr.SevenZipFile(file_path, mode='r') as archive:
                archive.extractall(path=extract_path)
        else:
            return {"error": "Unsupported file format. Upload .zip or .7z"}

        # Load & classify logs
        all_logs = load_logs_from_folder(extract_path)
        classified = classify_logs(all_logs)

    return {"classified_logs": classified}
