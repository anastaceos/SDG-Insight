# SDG Insight

**SDG Insight** is a powerful **OSINT (Open Source Intelligence)** tool designed to streamline cyber threat investigations by aggregating data from multiple cybersecurity intelligence sources. Built for **SOC analysts**, **cybersecurity professionals**, and **threat hunters**, SDG Insight automates the process of retrieving and analyzing intelligence on **IP addresses**, **domains**, **URLs**, and **file hashes** from industry-leading APIs.

The tool integrates with **VirusTotal**, **AbuseIPDB**, **Shodan**, **Have I Been Pwned (HIBP)**, **Hybrid Analysis**, and **URLScan.io**, ensuring comprehensive intelligence gathering for cyber threat analysis, incident response, and digital forensics.

## Key Features

- **Automated IOC Detection**: Input any IP, domain, URL, or hash, and SDG Insight determines its type and runs the appropriate OSINT checks.
- **Multi-Source Intelligence Gathering**: Fetches data from multiple cybersecurity APIs for a well-rounded investigation.
- **VirusTotal Integration**: Checks file hashes and URLs against VirusTotal’s massive malware database.
- **AbuseIPDB & Shodan Analysis**: Retrieves reputation scores and security insights on IP addresses.
- **Hybrid Analysis Lookup**: Analyzes file hashes for malware reports.
- **URLScan.io Integration**: Submits and retrieves real-time scans of URLs to detect phishing and malicious websites.
- **WHOIS Lookups**: Retrieves domain registration details for tracking ownership and age.
- **Formatted Reports**: Results are structured in an easy-to-read format for quick and efficient analysis.

## How It Works

1. **Enter an IOC (Indicator of Compromise)**: Simply type in an IP, domain, URL, or file hash.
2. **SDG Insight Automatically Identifies Its Type**: No need to specify whether it’s an IP, hash, or domain.
3. **Runs Relevant OSINT Queries**: Queries VirusTotal, AbuseIPDB, Shodan, URLScan.io, Hybrid Analysis, and WHOIS as needed.
4. **Displays Results in a Clear, Structured Format**: Makes it easy to assess threats.

## Example Use Cases

- **Incident Response**: Investigate suspicious IP addresses, URLs, and file hashes linked to security incidents.
- **Threat Intelligence**: Gather intelligence on malicious domains and compromised credentials.
- **Digital Forensics**: Analyze artifacts from security breaches or phishing campaigns.
- **SOC Operations**: Quickly retrieve threat reputation data for potential security threats.

## Why Use SDG Insight?

- **Time-Saving Automation**: Eliminates the need for manual OSINT lookups.
- **Comprehensive Coverage**: Aggregates intelligence from multiple top-tier cybersecurity sources.
- **User-Friendly**: Input a single IOC, and the tool does the rest.
- **Scalable & Extensible**: Can be expanded to include more OSINT APIs in the future.

## Getting Started

*(Add installation instructions here, e.g., prerequisites, setup steps, and how to configure API keys for VirusTotal, AbuseIPDB, etc.)*

```bash
# Example: Clone the repository
git clone https://github.com/yourusername/sdg-insight.git

# Install dependencies
pip install -r requirements.txt

# Run the tool
python sdg_insight.py
