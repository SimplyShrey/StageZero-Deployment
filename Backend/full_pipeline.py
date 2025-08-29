import subprocess
import json
import chardet
import requests
import os
from fastapi import FastAPI

app = FastAPI(title="Hackverse Log Pipeline")

os.chdir(os.path.dirname(os.path.abspath(__file__)))


# Config
LOAD_LOGS_SCRIPT = "load_logs.py"
CLASSIFY_LOGS_SCRIPT = "classify_logs.py"
ALL_LOGS_JSON = os.path.join(os.getcwd(), "all_logs.json")
CLASSIFIED_LOGS_JSON = os.path.join(os.getcwd(), "classified_logs.json")

WATSONX_API_KEY = "L23Q8Etg6haY0c2Z51OM9ToQQAMmvc7lFtyWrmxnhe2A"
WATSONX_URL = "https://eu-de.ml.cloud.ibm.com"
PROJECT_ID = "73c3e5ed-164f-4676-b5b1-eed6307148cd"

#Script run functions
def run_script(script_name):
    """Run a script in the current working directory and capture output."""
    print(f"\nRunning {script_name}...")
    result = subprocess.run(
        ["python", script_name],
        cwd=os.getcwd(),   # force current working directory
        capture_output=True,
        text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"ERROR in {script_name}:\n{result.stderr}")
        raise RuntimeError(f"{script_name} failed!")


def read_json_auto_encoding(file_path):
    """Load JSON file, auto-detect encoding if needed."""
    with open(file_path, "rb") as f:
        raw_data = f.read()
        result = chardet.detect(raw_data)
        encoding = result["encoding"] or "utf-8"
    with open(file_path, "r", encoding=encoding) as f:
        return json.load(f)
    

def send_to_watsonx(file_path):
    """Send classified logs to Watsonx."""
    classified_logs = read_json_auto_encoding(file_path)
    url = f"{WATSONX_URL}/v1/projects/{PROJECT_ID}/ingest"
    headers = {
        "Authorization": f"Bearer {WATSONX_API_KEY}",
        "Content-Type": "application/json"
    }
    response = requests.post(url, headers=headers, json=classified_logs)
    response.raise_for_status()
    print("Logs successfully sent to Watsonx!")


# #Main
# if __name__ == "__main__":
#     # Step 1: Load logs
#     run_script(LOAD_LOGS_SCRIPT)

#     # Step 2: Classify logs
#     run_script(CLASSIFY_LOGS_SCRIPT)

#     # Step 3: Send to Watsonx
#     print("\nSending classified logs to Watsonx...")
#     send_to_watsonx(CLASSIFIED_LOGS_JSON)

#API endpoints
@app.get("/load_logs")
def load_logs():
    output = run_script("load_logs.py")
    return {"status": "success", "output": output, "all_logs_file": ALL_LOGS_JSON}

@app.get("/classify_logs")
def classify_logs():
    output = run_script("classify_logs.py")
    return {"status": "success", "output": output, "classified_logs_file": CLASSIFIED_LOGS_JSON}

@app.get("/send_to_watsonx")
def send_logs():
    try:
        result = send_to_watsonx(CLASSIFIED_LOGS_JSON)
        return {"status": "success", "message": result}
    except requests.HTTPError as e:
        return {"status": "error", "message": str(e), "response": e.response.text}