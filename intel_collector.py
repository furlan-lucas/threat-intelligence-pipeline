# Import Python's built-in module for reading environment variables.
import os

# Import requests so the script can call web APIs.
import requests

# Import load_dotenv so Python can read values from the local .env file.
from dotenv import load_dotenv

# Import stix2 so Python can detect patterns
from stix2 import Bundle, Indicator, Malware, Relationship

# Import datetime for timestamps conversions
from datetime import datetime, timezone

# Load variables from .env into the current Python environment.
# This lets us use os.getenv() without hardcoding API keys in this file.
load_dotenv()


# Read API keys from the local .env file.
VT_API_KEY = os.getenv("VT_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")


# Stop immediately if any required key is missing.
# This avoids sending an API request with missing credentials.
if not all([VT_API_KEY, OTX_API_KEY, URLHAUS_AUTH_KEY]):
    raise EnvironmentError("One or more required API keys are missing.")


# This URLHaus endpoint returns 10 recently reported malware-delivery URLs.
URLHAUS_RECENT_URLS = (
    "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/30/"
)


# Send a GET request to URLHaus.
# The Auth-Key header proves that our request is authorized.
url_response = requests.get(
    URLHAUS_RECENT_URLS,
    headers={"Auth-Key": URLHAUS_AUTH_KEY},
    timeout=30,
)


# Raise an error if URLHaus returns an HTTP error, such as 401 or 500.
url_response.raise_for_status()


# Convert URLHaus's JSON response into Python data.
url_data = url_response.json()


# Extract the list of URL records from the response.
urls = url_data["urls"]


# Keep only URLs that URLHaus currently marks as online.
online_urls = [
    record
    for record in urls
    if record.get("url_status") == "online"
]


# Print collection results without visiting any malicious URLs.
print(f"Retrieved {len(urls)} URLHaus URL records.")
print(f"Active URL records: {len(online_urls)}")


# Display metadata for up to three active URLs.
for record in online_urls[:3]:
    print("\n--- Active URLHaus URL record ---")
    print(f"URL: {record.get('url')}")
    print(f"Status: {record.get('url_status')}")
    print(f"Tags: {record.get('tags')}")
    print(f"Date added: {record.get('date_added')}")


# This separate URLHaus endpoint returns recent malware payload metadata.
# It provides hashes and file types without downloading malware samples.
URLHAUS_RECENT_PAYLOADS = (
    "https://urlhaus-api.abuse.ch/v1/payloads/recent/limit/30/"
)


# Request recent payload metadata from URLHaus.
payload_response = requests.get(
    URLHAUS_RECENT_PAYLOADS,
    headers={"Auth-Key": URLHAUS_AUTH_KEY},
    timeout=30,
)


# Stop if URLHaus returns an HTTP error.
payload_response.raise_for_status()


# Convert the payload API response from JSON into Python data.
payload_data = payload_response.json()


# Extract the payload list.
payloads = payload_data["payloads"]
print(f"Retrieved {len(payloads)} URLHaus payload records.")

# Print metadata for up to three payloads.
for payload in payloads[:3]:
    print("\n--- URLHaus payload ---")
    print(f"SHA-256: {payload.get('sha256_hash')}")
    print(f"File type: {payload.get('file_type')}")
    print(f"Malware family: {payload.get('signature')}")


# Use only the first payload for a VirusTotal lookup.
# One lookup is intentional: it conserves Community API quota.
target_file_types = {"exe", "zip", "lnk", "pdf"}

target_payloads = [
    payload
    for payload in payloads
    if payload.get("file_type") in target_file_types
]

if not target_payloads:
    print("\nNo target payload types found in this batch.")
    raise SystemExit(0)

selected_payload = target_payloads[0]
sample_hash = selected_payload["sha256_hash"]

print("\n--- Selected payload for enrichment ---")
print(f"SHA-256: {sample_hash}")
print(f"File type: {selected_payload.get('file_type')}")
print(f"Malware family: {selected_payload.get('signature')}")


# VirusTotal lets us retrieve an existing file report using its SHA-256 hash.
vt_url = f"https://www.virustotal.com/api/v3/files/{sample_hash}"


# Ask VirusTotal for the existing report.
vt_response = requests.get(
    vt_url,
    headers={"x-apikey": VT_API_KEY},
    timeout=30,
)


# A 404 means VirusTotal does not have a report for this hash.
# This is normal for new or uncommon samples, so the script should continue.
if vt_response.status_code == 404:
    print("\n--- VirusTotal enrichment ---")
    print(f"SHA-256: {sample_hash}")
    print("VirusTotal report: not available (HTTP 404)")
    print("Result: retain the URLHaus SHA-256 as an unenriched indicator.")

else:
    # Raise an error for unexpected HTTP failures, such as 401 or 429.
    vt_response.raise_for_status()

    # Extract the nested file attributes from VirusTotal's JSON response.
    vt_attributes = vt_response.json()["data"]["attributes"]

    # Extract the antivirus-engine detection counts.
    vt_stats = vt_attributes["last_analysis_stats"]

    # Count all engines that returned the main verdict categories.
    total_engines = sum(
        vt_stats.get(category, 0)
        for category in [
            "malicious",
            "suspicious",
            "undetected",
            "harmless",
        ]
    )

    # Count the engines that flagged the file as malicious or suspicious.
    flagged_engines = (
        vt_stats.get("malicious", 0)
        + vt_stats.get("suspicious", 0)
    )

    # Print the enrichment result.
    print("\n--- VirusTotal enrichment ---")
    print(f"SHA-256: {vt_attributes.get('sha256')}")
    print(f"Malicious detections: {vt_stats.get('malicious', 0)}")
    print(f"Suspicious detections: {vt_stats.get('suspicious', 0)}")
    print(f"Undetected: {vt_stats.get('undetected', 0)}")
    print(f"Detection ratio: {flagged_engines}/{total_engines}")

# Use the URLHaus malware label when available.
# Otherwise use a transparent placeholder instead of guessing a family name.
malware_name = selected_payload.get("signature") or "Unknown malware"

# URLHaus returns a date like: 2026-09-18 22:34:44
# Convert it into the timestamp format STIX requires.
urlhaus_firstseen = selected_payload["firstseen"]

valid_from = datetime.strptime(
    urlhaus_firstseen,
    "%Y-%m-%d %H:%M:%S",
).replace(tzinfo=timezone.utc)


# Create an Indicator that defenders can use to match the SHA-256 hash.
hash_indicator = Indicator(
    name=f"Malicious file hash: {sample_hash}",
    pattern=f"[file:hashes.'SHA-256' = '{sample_hash}']",
    pattern_type="stix",
    valid_from=valid_from,
    description=(
        "SHA-256 hash observed in the URLHaus recent payload feed."
    ),
)

# Create a STIX object describing the malware payload.
malware = Malware(
    name=malware_name,
    is_family=False,
    description=(
        f"URLHaus-reported payload with file type: "
        f"{selected_payload.get('file_type', 'unknown')}."
    ),
)

# Link the file-hash indicator to the malware object.
indicator_relationship = Relationship(
    relationship_type="indicates",
    source_ref=hash_indicator.id,
    target_ref=malware.id,
    description="The file-hash indicator identifies this malware payload.",
)

# Combine the objects into one valid STIX bundle.
stix_bundle = Bundle(
    objects=[
        hash_indicator,
        malware,
        indicator_relationship,
    ]
)

# Save structured threat intelligence to a local JSON file.
with open("stix_output.json", "w", encoding="utf-8") as output_file:
    output_file.write(stix_bundle.serialize(pretty=True))

print("\nSTIX output saved to stix_output.json")