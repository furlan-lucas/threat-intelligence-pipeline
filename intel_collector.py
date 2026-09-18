# This script collects recent malware-delivery metadata from URLHaus,
# optionally enriches one payload hash with VirusTotal, and creates
# a STIX 2.1 JSON file for defensive threat-intelligence use.

# Read environment variables, such as API keys.
import os

# Make HTTP requests to APIs.
import requests

# Convert URLHaus date text into a STIX-compatible UTC timestamp.
from datetime import datetime, timezone

# Load local values from the .env file.
from dotenv import load_dotenv

# Create standardized STIX threat-intelligence objects.
from stix2 import Bundle, Indicator, Malware, Relationship


# Load API keys from the local .env file.
# The .env file is ignored by Git and must never be committed.
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")


# Stop early if a required environment variable is missing.
if not all([VT_API_KEY, OTX_API_KEY, URLHAUS_AUTH_KEY]):
    raise EnvironmentError("One or more required API keys are missing.")


# URLHaus API endpoints.
# These requests retrieve metadata only. This script never downloads samples.
URLHAUS_RECENT_URLS = (
    "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/30/"
)

URLHAUS_RECENT_PAYLOADS = (
    "https://urlhaus-api.abuse.ch/v1/payloads/recent/limit/30/"
)


# Send a request for recent malware-distribution URL records.
url_response = requests.get(
    URLHAUS_RECENT_URLS,
    headers={"Auth-Key": URLHAUS_AUTH_KEY},
    timeout=30,
)

# Stop if URLHaus returns an unexpected HTTP error.
url_response.raise_for_status()

# Turn the JSON response into Python data.
url_data = url_response.json()

# Extract the list of URL records.
urls = url_data["urls"]


# Keep only URLs currently marked online by URLHaus.
online_urls = [
    record
    for record in urls
    if record.get("url_status") == "online"
]

print(f"Retrieved {len(urls)} URLHaus URL records.")
print(f"Active URL records: {len(online_urls)}")


# Print a few records for visibility.
# Do not open, browse, download, or execute these URLs.
for record in online_urls[:3]:
    print("\n--- Active URLHaus URL record ---")
    print(f"URL: {record.get('url')}")
    print(f"Status: {record.get('url_status')}")
    print(f"Tags: {record.get('tags')}")
    print(f"Date added: {record.get('date_added')}")


# Stop safely if URLHaus has no currently online URLs.
if not online_urls:
    print("\nNo active URLHaus URL records were found in this batch.")
    raise SystemExit(0)


# Request recent payload metadata from URLHaus.
payload_response = requests.get(
    URLHAUS_RECENT_PAYLOADS,
    headers={"Auth-Key": URLHAUS_AUTH_KEY},
    timeout=30,
)

payload_response.raise_for_status()

# Extract the payload list from the API response.
payload_data = payload_response.json()
payloads = payload_data["payloads"]

print(f"\nRetrieved {len(payloads)} URLHaus payload records.")


# Print a few payload records for visibility.
for payload in payloads[:3]:
    print("\n--- URLHaus payload ---")
    print(f"SHA-256: {payload.get('sha256_hash')}")
    print(f"File type: {payload.get('file_type')}")
    print(f"Malware family: {payload.get('signature')}")


# These file types match the project focus on common phishing-delivered files.
target_file_types = {"exe", "zip", "lnk", "pdf"}

# Keep only payloads with one of our target file types.
target_payloads = [
    payload
    for payload in payloads
    if payload.get("file_type") in target_file_types
]


# Stop safely when this live batch contains no target file type.
if not target_payloads:
    print("\nNo EXE, ZIP, LNK, or PDF payloads were found in this batch.")
    raise SystemExit(0)


# Select one payload for enrichment.
# One VirusTotal lookup per run conserves Community API quota.
selected_payload = target_payloads[0]
sample_hash = selected_payload["sha256_hash"]

print("\n--- Selected payload for enrichment ---")
print(f"SHA-256: {sample_hash}")
print(f"File type: {selected_payload.get('file_type')}")
print(f"Malware family: {selected_payload.get('signature')}")


# Use the SHA-256 hash to request an existing VirusTotal file report.
vt_url = f"https://www.virustotal.com/api/v3/files/{sample_hash}"

vt_response = requests.get(
    vt_url,
    headers={"x-apikey": VT_API_KEY},
    timeout=30,
)


# A 404 means VirusTotal has no report for this exact file hash.
# This is normal with new or less-common files.
if vt_response.status_code == 404:
    print("\n--- VirusTotal enrichment ---")
    print(f"SHA-256: {sample_hash}")
    print("VirusTotal report: not available (HTTP 404)")
    print("Result: retain the URLHaus SHA-256 as an unenriched indicator.")

else:
    # Stop for other errors, such as invalid credentials or API rate limits.
    vt_response.raise_for_status()

    # Extract scan statistics from the VirusTotal response.
    vt_attributes = vt_response.json()["data"]["attributes"]
    vt_stats = vt_attributes["last_analysis_stats"]

    # Count engines that returned one of the primary verdict types.
    total_engines = sum(
        vt_stats.get(category, 0)
        for category in [
            "malicious",
            "suspicious",
            "undetected",
            "harmless",
        ]
    )

    # Count engines that found the payload malicious or suspicious.
    flagged_engines = (
        vt_stats.get("malicious", 0)
        + vt_stats.get("suspicious", 0)
    )

    print("\n--- VirusTotal enrichment ---")
    print(f"SHA-256: {vt_attributes.get('sha256')}")
    print(f"Malicious detections: {vt_stats.get('malicious', 0)}")
    print(f"Suspicious detections: {vt_stats.get('suspicious', 0)}")
    print(f"Undetected: {vt_stats.get('undetected', 0)}")
    print(f"Detection ratio: {flagged_engines}/{total_engines}")


# Select one online URL for the STIX URL indicator.
selected_url_record = online_urls[0]
malicious_url = selected_url_record["url"]


# Use the malware-family label only when URLHaus provides one.
# Do not guess a malware family from the file type.
malware_name = selected_payload.get("signature") or "Unknown malware"


# URLHaus uses a date format like: 2026-09-18 22:34:44
# STIX needs a UTC-aware datetime value.
urlhaus_firstseen = selected_payload["firstseen"]

valid_from = datetime.strptime(
    urlhaus_firstseen,
    "%Y-%m-%d %H:%M:%S",
).replace(tzinfo=timezone.utc)


# Create a STIX Indicator for the payload SHA-256.
hash_indicator = Indicator(
    name=f"Malicious file hash: {sample_hash}",
    pattern=f"[file:hashes.'SHA-256' = '{sample_hash}']",
    pattern_type="stix",
    valid_from=valid_from,
    description="SHA-256 hash observed in the URLHaus recent payload feed.",
)


# Create a second STIX Indicator for the malware-delivery URL.
url_indicator = Indicator(
    name="Malware-delivery URL from URLHaus",
    pattern=f"[url:value = '{malicious_url}']",
    pattern_type="stix",
    valid_from=valid_from,
    description="URL reported by URLHaus as a malware-distribution location.",
)


# Describe the malware payload in STIX.
malware = Malware(
    name=malware_name,
    is_family=False,
    description=(
        "URLHaus-reported payload with file type: "
        f"{selected_payload.get('file_type', 'unknown')}."
    ),
)


# Link the file-hash Indicator to the Malware object.
hash_to_malware_relationship = Relationship(
    relationship_type="indicates",
    source_ref=hash_indicator.id,
    target_ref=malware.id,
    description="The file-hash indicator identifies this malware payload.",
)


# Link the malware-delivery URL Indicator to the same Malware object.
url_to_malware_relationship = Relationship(
    relationship_type="indicates",
    source_ref=url_indicator.id,
    target_ref=malware.id,
    description="The URL indicator identifies the malware-delivery location.",
)


# Package every STIX object together in a single JSON Bundle.
stix_bundle = Bundle(
    objects=[
        hash_indicator,
        url_indicator,
        malware,
        hash_to_malware_relationship,
        url_to_malware_relationship,
    ]
)


# Write the STIX Bundle to a readable JSON output file.
with open("stix_output.json", "w", encoding="utf-8") as output_file:
    output_file.write(stix_bundle.serialize(pretty=True))

print("\nSTIX output saved to stix_output.json")