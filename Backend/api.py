import json
import os
import requests
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

# Paths & Configs
CLASSIFIED_LOGS_JSON = os.path.join(os.getcwd(), "classified_logs.json")
WATSONX_API_KEY = "L23Q8Etg6haY0c2Z51OM9ToQQAMmvc7lFtyWrmxnhe2A"
WATSONX_URL = "https://eu-de.ml.cloud.ibm.com"
PROJECT_ID = "YOUR_PROJECT_ID"

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
def run_command(req: CommandRequest):
    """Run a backend command from frontend input."""
    cmd = req.command
    # Simulate backend execution (replace with real logic)
    result = f"Executed command: {cmd}"
    return {"output": result}
