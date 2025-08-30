import os
import json
import pandas as pd
import zipfile
import tempfile
import py7zr
import requests
import shutil
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# Allow React frontend
app.add_middleware(
    CORSMiddleware,
    # allow_origins=["http://localhost:3000"],  # change if needed
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

MITRE_FILE = "mitre_data/enterprise-attack.json"

# Paths & Configs
UPLOAD_DIR = "uploads"
CLASSIFIED_LOGS_JSON = os.path.join(os.getcwd(), "classified_logs.json")
WATSONX_API_KEY = "L23Q8Etg6haY0c2Z51OM9ToQQAMmvc7lFtyWrmxnhe2A"
WATSONX_URL = "https://eu-de.ml.cloud.ibm.com"
PROJECT_ID = "f648a793-9b86-460d-b31b-af8de0f66fde"

# --- Models ---
class CommandRequest(BaseModel):
    command: str

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
async def upload_logs(action: str = Form(...), file: UploadFile = None, password: str = Form(None)):
    print(f"Received password: {password}")
    if action == "check-status":
        return {"output": "Server is running."}
    if action == "analyze-log":
        if not file:
            return JSONResponse({"output": "No file uploaded."}, status_code=400)
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, file.filename)
            with open(file_path, "wb") as f:
                f.write(await file.read())

            # Try to extract .7z archive
            try:
                with py7zr.SevenZipFile(file_path, mode='r', password=password) as archive:
                    archive.extractall(path=tmpdir)
                # You can process extracted files here
                extracted_files = os.listdir(tmpdir)
                return {"output": f"Archive extracted! Files: {extracted_files}"}
            except py7zr.exceptions.PasswordRequired:
                return {"output": "Password is required for extracting given archive."}
            except py7zr.exceptions.Bad7zFile:
                return {"output": "Invalid or corrupted archive."}
            except Exception as e:
                return {"output": f"Error extracting archive: {str(e)}"}
    return {"output": "Unknown action."}

@app.get("/classify")
def classify_logs_endpoint():
    """Return locally classified logs."""
    try:
        with open(CLASSIFIED_LOGS_JSON, "r", encoding="utf-8") as f:
            classified_logs = json.load(f)
        return classified_logs
    except FileNotFoundError:
        return {"error": "No classified logs found. Please upload and analyze logs first."}

@app.get("/sample")
def sample_log():
    """Test endpoint to verify API is running."""
    return {"example": "Log classification API running locally."}

@app.get("/send_to_watsonx")
def send_to_watsonx():
    """Send classified logs to Watsonx project."""
    try:
        with open(CLASSIFIED_LOGS_JSON, "r", encoding="utf-8") as f:
            classified_logs = json.load(f)

        url = f"{WATSONX_URL}/v1/projects/{PROJECT_ID}/ingest"
        headers = {
            "Authorization": f"Bearer {WATSONX_API_KEY}",
            "Content-Type": "application/json"
        }

        response = requests.post(url, headers=headers, json=classified_logs)
        response.raise_for_status()
        return {"status": "success", "watsonx_response": response.json()}
    except FileNotFoundError:
        return {"status": "error", "detail": "No classified logs found."}
    except requests.exceptions.RequestException as e:
        return {"status": "error", "detail": str(e)}

@app.post("/run-command")
async def run_command(action: str = Form(...), file: UploadFile = File(None)):
    output = ""
    if action == "analyze-log":
        if not file:
            return {"output": "No file uploaded."}
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        file_path = os.path.join(UPLOAD_DIR, file.filename)
        with open(file_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
        output = f"File {file.filename} received and ready for analysis."
        print(f"[CLI] {output}")  # prints to your terminal
    elif action == "check-status":
        output = "Server is running."
        print(f"[CLI] {output}")  # prints to your terminal
    return {"output": output}

@app.post("/api/report")
async def get_report(logs: str = Form(...)):
    """Generate report from logs text."""
    try:
        all_logs = [{"filename": "input", "text": logs}]
        classified = classify_logs(all_logs)
        report = f"Report generated. Classified {len(classified)} entries."
        return {"report": report}
    except Exception as e:
        return {"report": f"Error generating report: {str(e)}"}