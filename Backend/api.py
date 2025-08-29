import json
import os
import requests
from fastapi import FastAPI
from pydantic import BaseModel
import shutil
from fastapi import FastAPI, File, UploadFile, Form

app = FastAPI()

# Paths & Configs
UPLOAD_DIR = "uploads"
CLASSIFIED_LOGS_JSON = os.path.join(os.getcwd(), "classified_logs.json")
WATSONX_API_KEY = "L23Q8Etg6haY0c2Z51OM9ToQQAMmvc7lFtyWrmxnhe2A"
WATSONX_URL = "https://eu-de.ml.cloud.ibm.com"
PROJECT_ID = "f648a793-9b86-460d-b31b-af8de0f66fde"

# --- Models ---
class CommandRequest(BaseModel):
    command: str

# --- Endpoints ---
@app.get("/classify")
def classify_logs():
    """Return locally classified logs."""
    with open(CLASSIFIED_LOGS_JSON, "r", encoding="utf-8") as f:
        classified_logs = json.load(f)
    return classified_logs

@app.get("/sample")
def sample_log():
    """Test endpoint to verify API is running."""
    return {"example": "Log classification API running locally."}

@app.get("/send_to_watsonx")
def send_to_watsonx():
    """Send classified logs to Watsonx project."""
    with open(CLASSIFIED_LOGS_JSON, "r", encoding="utf-8") as f:
        classified_logs = json.load(f)

    url = f"{WATSONX_URL}/v1/projects/{PROJECT_ID}/ingest"
    headers = {
        "Authorization": f"Bearer {WATSONX_API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(url, headers=headers, json=classified_logs)
        response.raise_for_status()
        return {"status": "success", "watsonx_response": response.json()}
    except requests.exceptions.RequestException as e:
        return {"status": "error", "detail": str(e)}


@app.post("/run-command")
async def run_command(action: str = Form(...), file: UploadFile | None = File(None)):
    output = ""
    if action == "analyze-log":
        if not file:
            return {"output": "No file uploaded."}
        os.makedirs("uploads", exist_ok=True)
        file_path = os.path.join("uploads", file.filename)
        with open(file_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
        output = f"File {file.filename} received and ready for analysis."
        print(f"[CLI] {output}")  # prints to your terminal
    elif action == "check-status":
        output = "Server is running."
        print(f"[CLI] {output}")  # prints to your terminal
    return {"output": output}


