from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import json
import load_logs
import classify_logs
import requests
import os

app = FastAPI()
CLASSIFIED_LOGS_JSON = "classified_logs.json"
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# Watsonx details
WATSONX_API_KEY = "IkeCx8RlZEmXkPPq38q1EjHur5bHBo9cF-CfeAsHt7rb"
WATSONX_URL = "https://eu-de.ml.cloud.ibm.com"
PROJECT_ID = "f648a793-9b86-460d-b31b-af8de0f66fde"

@app.post("/upload-logs")
async def upload_logs(file: UploadFile = File(...)):
    contents = await file.read()
    json_logs = load_logs.process_file(contents)  # you may need to adjust load_logs.py
    classified = classify_logs.classify(json_logs)
    with open(CLASSIFIED_LOGS_JSON, "w", encoding="utf-8") as f:
        json.dump(classified, f, indent=2)
    return {"classified_logs": classified}

@app.post("/chat")
async def chat(payload: dict):
    user_message = payload.get("message", "")
    classified_logs = payload.get("classified_logs", [])

    prompt = f"Logs: {classified_logs}\nUser: {user_message}\nPlease provide analysis and report."
    
    url = f"{WATSONX_URL}/v1/projects/{PROJECT_ID}/ingest"
    headers = {"Authorization": f"Bearer {WATSONX_API_KEY}", "Content-Type": "application/json"}
    response = requests.post(url, headers=headers, json={"input": prompt})
    response.raise_for_status()
    return {"response": response.json()}
