# Threat Intelligence Advisory: URLHaus-Observed Malware Delivery Activity

## Executive Summary

Recent URLHaus telemetry identified active URLs associated with malware delivery and payloads including ZIP and EXE files. The pipeline captured SHA-256 indicators and attempted VirusTotal enrichment; some newly observed payloads did not yet have an available VirusTotal report. Organizations should treat the observed URLs and file hashes as potentially malicious, block them where appropriate, and hunt for matching web-proxy, DNS, email, and endpoint telemetry. This advisory is based on infrastructure and payload metadata and does not attribute the activity to a specific threat actor or campaign.

## Detection and Hunting

Defenders should search security logs for the listed URLHaus URLs, domains, IP addresses, and SHA-256 hashes.

- Search web-proxy, secure web gateway, firewall, and DNS logs for connections to the observed indicators.
- Search email-security logs for messages containing the observed URLs or attachments matching the file hashes.
- Search endpoint detection and response (EDR) telemetry for files with the listed SHA-256 hashes.
- Investigate endpoints that downloaded a matching file, executed an unexpected EXE, or contacted a matching URL.
- Treat a VirusTotal 404 response as “no report available,” not as evidence that a file is safe.

## Recommended Actions

1. Block confirmed malicious URLs, domains, and IP addresses at DNS, proxy, firewall, and email-security controls.
2. Block or quarantine files that match the collected SHA-256 indicators.
3. Review downloads of high-risk file types, especially EXE files and archives containing executable content.
4. Use application allowlisting and endpoint controls to reduce unauthorized executable launches.
5. Preserve endpoint and network logs before remediation so the team can investigate scope and possible affected hosts.
6. Train users to report suspicious links and unexpected downloads.

## Indicators of Compromise

The indicators below were collected from the live URLHaus feed at the time the pipeline ran. They are time-sensitive, so defenders should validate them against current internal telemetry before blocking or escalating.

### Selected File Hash

| Indicator Type | Value | Context |
|---|---|---|
| SHA-256 | `b439f6d7ef6902f8d2873f1f92e4c461c2edd63357b0593734e6d149be224624` | URLHaus payload metadata; file type: EXE; VirusTotal report unavailable at collection time |

### Selected Malware-Delivery URL

| Indicator Type | Value | Context |
|---|---|---|
| URL | `http://219.155.202.224:39256/bin.sh` | URLHaus marked the URL as online when collected |

## Evidence and Limitations

- Source: URLHaus recent URL and payload metadata feeds.
- Enrichment source: VirusTotal file-report endpoint.
- The selected payload had no VirusTotal report available during collection.
- A missing VirusTotal report does not mean that a file is benign.
- The URL, payload, and any malware label can change as threat-intelligence feeds update.
- This advisory does not confirm delivery through email, user execution, affected hosts, or a specific threat actor.