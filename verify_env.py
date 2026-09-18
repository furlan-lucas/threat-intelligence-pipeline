import os
from dotenv import load_dotenv

load_dotenv()

required_keys = [
    "VT_API_KEY",
    "OTX_API_KEY",
    "URLHAUS_AUTH_KEY",
]

for key in required_keys:
    status = "configured" if os.getenv(key) else "missing"
    print(f"{key}: {status}")