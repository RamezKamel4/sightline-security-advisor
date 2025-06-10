
import os
from dotenv import load_dotenv
from openai import OpenAI

# Load environment variables from .env file
load_dotenv()

print(f"Attempting to load .env. Key found: {os.getenv('OPENAI_KEY_New')}")

# --- OpenAI API Key Configuration ---
OPENAI_API_KEY = os.getenv("OPENAI_KEY_New")

if not OPENAI_API_KEY:
    print("WARNING: OpenAI API key is not set in the environment or .env file.")
    OPENAI_API_KEY = "YOUR_OPENAI_API_KEY_FALLBACK_IF_NOT_SET"

# Initialize client
client = OpenAI(api_key=OPENAI_API_KEY)
