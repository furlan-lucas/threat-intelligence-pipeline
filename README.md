# Threat Intelligence Pipeline

A Python project that collects recent malware-delivery intelligence from URLHaus, enriches one file hash with VirusTotal, and exports selected indicators as a STIX 2.1 bundle.

> Defensive use only. This project collects and processes threat-intelligence metadata. It does not download, open, visit, or execute malicious files or URLs.

## Features

- Retrieves recent malware-delivery URL metadata from URLHaus.
- Filters URLHaus records to keep URLs currently marked as `online`.
- Retrieves recent payload metadata, including SHA-256 hashes and file types.
- Selects one target payload type: EXE, ZIP, LNK, or PDF.
- Looks up the selected SHA-256 hash with the VirusTotal API.
- Handles a VirusTotal HTTP 404 response safely as “report not available.”
- Creates STIX 2.1 Indicators for a SHA-256 hash and malware-delivery URL.
- Creates a STIX Malware object and `indicates` Relationships.
- Exports structured threat intelligence to `stix_output.json`.
- Documents findings and defensive actions in `ADVISORY.md`.

## Project Structure

```text
threat-intelligence-pipeline/
├── intel_collector.py     # Main collection, enrichment, and STIX export script
├── requirements.txt       # Python dependencies
├── .env.example           # Template for required API variable names
├── .gitignore             # Prevents secrets and generated output from being committed
├── ADVISORY.md            # Detection, hunting, and response guidance
└── stix_output.json       # Generated locally when the script runs
```

## Requirements

- Python 3.10 or later
- A URLHaus Auth-Key
- A VirusTotal API key
- An AlienVault OTX API key

URLHaus provides a community API for querying malware URL intelligence and requires an Auth-Key for API access. VirusTotal API v3 supports retrieving file reports using file hashes such as SHA-256.

## Installation

Clone the repository and move into the project folder:

```bash
git clone [https://github.com/YOUR-USERNAME/threat-intelligence-pipeline.git](https://github.com/YOUR-USERNAME/threat-intelligence-pipeline.git)
cd threat-intelligence-pipeline
```

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

## API Configuration

Create your local `.env` file by copying the safe template:

```bash
cp .env.example .env
```

Open `.env` and add your real API credentials:

```text
VT_API_KEY=your_virustotal_api_key
OTX_API_KEY=your_otx_api_key
URLHAUS_AUTH_KEY=your_urlhaus_auth_key
```

Never commit `.env` to GitHub. It contains private API credentials and is excluded by `.gitignore`.

## Usage

Run the script from the project folder:

```bash
python intel_collector.py
```

The script prints:

- The number of URLHaus URL records retrieved.
- The number of active URL records.
- Metadata for a small number of recent URL and payload records.
- The selected file hash for enrichment.
- VirusTotal detection statistics, when a report is available.
- A confirmation that the STIX file was created.

## Output

Running the script creates:

```text
stix_output.json
```

The STIX bundle contains:

- A SHA-256 file-hash Indicator.
- A malware-delivery URL Indicator.
- A Malware object using the URLHaus label when available.
- `indicates` relationships connecting the Indicators to the Malware object.

STIX is a standard language for representing and exchanging cyber threat intelligence. In this project, the `indicates` relationship connects an Indicator to the malware it can help defenders detect.

## Advisory

`ADVISORY.md` contains:

- An evidence-based executive summary.
- Detection and hunting guidance.
- Recommended defensive actions.
- Selected indicators of compromise.
- Evidence limitations and attribution cautions.

A VirusTotal `404` response means VirusTotal does not have a report available for that exact hash. It does not prove that the file is safe.

## Limitations

- The pipeline uses live threat-intelligence feeds, so results can change every time the script runs.
- The script performs only one VirusTotal lookup per execution to conserve API quota.
- A malware-delivery URL or hash alone does not prove a specific victim was compromised.
- The project does not attribute activity to a threat actor.
- OTX is loaded as a required API key for future enrichment work but is not yet queried by the current script.
- `stix_output.json` is intentionally ignored by Git because it changes with each live collection run.

## Safe Handling

- Do not visit URLs printed by the script.
- Do not download or execute payloads.
- Use an isolated lab environment for security research.
- Use the collected indicators for defensive blocking, alerting, and log hunting only.

## References

- URLHaus Community API: https://urlhaus.abuse.ch/api/
- VirusTotal API v3: https://docs.virustotal.com/reference/overview
- OASIS STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
