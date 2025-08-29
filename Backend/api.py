# from fastapi import FastAPI
# import json
# import os

# app = FastAPI()

# CLASSIFIED_LOGS_JSON = os.path.join(os.getcwd(), "classified_logs.json")

# @app.get("/classify")
# def classify_logs():
#     with open(CLASSIFIED_LOGS_JSON, "r", encoding="utf-8") as f:
#         classified_logs = json.load(f)
#     return classified_logs
    

# @app.get("/sample")
# def sample_log():
#     return {"example": "Log classification API running locally."}
import json
import os
import requests
from fastapi import FastAPI

app = FastAPI()
CLASSIFIED_LOGS_JSON = os.path.join(os.getcwd(), "classified_logs.json")

WATSONX_API_KEY = "L23Q8Etg6haY0c2Z51OM9ToQQAMmvc7lFtyWrmxnhe2A"
WATSONX_URL = "https://eu-de.ml.cloud.ibm.com"
PROJECT_ID = "YOUR_PROJECT_ID"

@app.get("/send_to_watsonx")
def send_to_watsonx():
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
