from ibm_watsonxdata import DataClient
from ibm_watsonx_ai import AIClient
from ibm_watson import AssistantV2

# Watsonx API
API_KEY = "YOUR_WATSONX_API_KEY"
URL = "https://YOUR_WATSONX_URL"

# Initialize clients
data_client = DataClient(api_key=API_KEY, url=URL)
ai_client = AIClient(api_key=API_KEY, url=URL)

# watsonx.data collection ID for storing logs
COLLECTION_ID = "your_cloud_collection_id"

# AI model ID for MITRE ATT&CK classification
AI_MODEL_ID = "mitre-attck-classifier"

# Watson Assistant credentials
ASSISTANT_API_KEY = "YOUR_ASSISTANT_API_KEY"
ASSISTANT_URL = "https://YOUR_ASSISTANT_URL"
ASSISTANT_ID = "YOUR_ASSISTANT_ID"

assistant = AssistantV2(
    version='2025-08-29',
    iam_apikey=ASSISTANT_API_KEY,
    url=ASSISTANT_URL
)

# Path to your local logs folder
LOG_FOLDER = "logs_folder"