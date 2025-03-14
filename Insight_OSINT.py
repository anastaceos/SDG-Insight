import requests
import time
import json
import socket
import whois
import re
from urllib.parse import urlparse
import validators
import base64
import urllib.parse
import os
from dotenv import load_dotenv

#load_dotenv()  # Load API keys from a .env file

#VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
#ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
#HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")

# API Keys (Set your own keys here)
VIRUSTOTAL_API_KEY = "ca1e9b61569e86434c6e5e30345c6a453e51b3f0197148c3d51af895968bd4ba"
ABUSEIPDB_API_KEY = "fb7a1175a449e459010776fea3d4ec2832b647da0422384efbbadc4ad594479f7efb6983dfe522ea"
HYBRID_ANALYSIS_API_KEY = "6rnakmkj6ed49416v459v1fl75bbd7e3abafiwmf99ea95f84ow80g0ce3464a5d"
URLSCAN_API_KEY = "01958a4b-1aec-7001-9c07-e01053a8158b"

# Headers for APIs
VT_HEADERS = {
    "accept": "application/json",
    "x-apikey": VIRUSTOTAL_API_KEY
}
ABUSEIPDB_HEADERS = {
    "Key": ABUSEIPDB_API_KEY, 
    "Accept": "application/json"
}
HYBRID_ANALYSIS_HEADERS = {
    "User-Agent": "Falcon Sandbox",
    "api-key": HYBRID_ANALYSIS_API_KEY,
    "accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded"
}
URLSCAN_HEADERS = {
    "API-Key": URLSCAN_API_KEY.strip(),  # Ensure no extra spaces
    "Content-Type": "application/json"
}
    
def determine_ioc_type(ioc):
    if validators.ipv4(ioc):
        return "ipv4"
    elif validators.ipv6(ioc):
        return "ipv6"
    elif validators.domain(ioc):
        return "domain"
    elif validators.url(ioc):
        return "url"
    elif re.fullmatch(r"^[a-fA-F0-9]{32}$", ioc):
        return "md5"
    elif re.fullmatch(r"^[a-fA-F0-9]{40}$", ioc):
        return "sha1"
    elif re.fullmatch(r"^[a-fA-F0-9]{64}$", ioc):
        return "sha256"
    elif validators.email(ioc):
        return "email"
    else:
        return "unknown"

#  Submits a URL to VirusTotal for scanning and retrieves the analysis report.
def query_virustotal_url(url):
   
    # Step 1: Submit the URL for scanning
    submit_url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(submit_url, headers=VT_HEADERS, data={"url": url})
    
    if response.status_code != 200:
        return {"error": f"Failed to submit URL to VirusTotal - {response.status_code}: {response.text}"}

    # Extracting the scan ID from the response
    try:
        scan_id = response.json()["data"]["id"]
    except KeyError:
        return {"error": "Failed to extract scan ID from VirusTotal response"}

    # Step 2: Wait a few seconds for the scan to complete
    time.sleep(30)  # Give VirusTotal time to analyze the URL

    # Step 3: Retrieve the analysis report
    report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    report_response = requests.get(report_url, headers=VT_HEADERS)

    if report_response.status_code != 200:
        return {"error": f"Failed to retrieve report from VirusTotal - {report_response.status_code}: {report_response.text}"}

    report_data = report_response.json()

    #analysis_attributes = report_data["data"]["attributes"]

    #print(json.dumps(report_data, indent=4))

    # Extract relevant results
    return {
        "virustotal: status": report_data["data"]["attributes"]["status"],
        "virustotal: reputation": report_data["data"]["attributes"]["stats"],
        #"tags": analysis_attributes.get("tags", []),
        #"VT permalink": f"https://www.virustotal.com/gui/url/{scan_id}"
    }

# Function to query VirusTotal for an IP address
def query_virustotal_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(url, headers=VT_HEADERS)
    if response.status_code == 200:
        data = response.json()
        #print(json.dumps(data, indent=4))
        return {
            "virustotal: country": data.get("data", {}).get("attributes", {}).get("country", "Unknown"),
            "virustotal: as_owner": data.get("data", {}).get("attributes", {}).get("as_owner", "Unknown"),
            "virustotal: reputation": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
            "virustotal: malicious_vote": data.get("data", {}).get("attributes", {}).get("total_votes", {}).get("malicious", 0),
            "virustotal: harmless_vote": data.get("data", {}).get("attributes", {}).get("total_votes", {}).get("harmless", 0),
            "virustotal: tags": data.get("data", {}).get("attributes", {}).get("tags", [])
        }
    else:
        return {"ip": ip, "error": f"Failed to retrieve from VirusTotal - Status Code: {response.status_code}, Message: {response.text}"}

# Function to query VirusTotal for a file hash
def query_virustotal_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(url, headers=VT_HEADERS)
    if response.status_code == 200:
        data = response.json()
        #print(json.dumps(data, indent=4))
        return {
            "virustotal: reputation": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
            "virustotal: malicious_vote": data.get("data", {}).get("attributes", {}).get("total_votes", {}).get("malicious", 0),
            "virustotal: harmless_vote": data.get("data", {}).get("attributes", {}).get("total_votes", {}).get("harmless", 0),
            "virustotal: tags": data.get("data", {}).get("attributes", {}).get("tags", [])
        }
    else:
        return {"hash": file_hash, "error": f"Failed to retrieve from VirusTotal - Status Code: {response.status_code}, Message: {response.text}"}

# Function to query VirusTotal for a domain
def query_virustotal_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    response = requests.get(url, headers=VT_HEADERS)
    if response.status_code == 200:
        data = response.json()
        print(json.dumps(data, indent=4))
        return {
            "virustotal: categories": data.get("data", {}).get("attributes", {}).get("categories", "Unknown"),
            "virustotal: registrar": data.get("data", {}).get("attributes", {}).get("registrar", "Unknown"),
            "virustotal: reputation": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
            "virustotal: malicious_vote": data.get("data", {}).get("attributes", {}).get("total_votes", {}).get("malicious", 0),
            "virustotal: harmless_vote": data.get("data", {}).get("attributes", {}).get("total_votes", {}).get("harmless", 0),
            "virustotal: tags": data.get("data", {}).get("attributes", {}).get("tags", [])
        }
    else:
        return {"domain": domain, "error": f"Failed to retrieve from VirusTotal - Status Code: {response.status_code}, Message: {response.text}"}

# Function to submit a URL to URLScan.io for analysis  
def submit_urlscan(url):
    submit_url = "https://urlscan.io/api/v1/scan/"
    payload = {"url": url, "visibility": "public"}  # Set "private" for non-public scans

    response = requests.post(submit_url, headers=URLSCAN_HEADERS, json=payload)

    if response.status_code != 200:
        return {"error": f"Failed to submit URL to URLScan.io - {response.status_code}: {response.text}"}

    data = response.json()
    return {
        "url": url,
        "scan_id": data.get("uuid"),
        "urlscan_permalink": data.get("result")  # Direct link to the scan report
    }

# Retrieves the scan report from URLScan.io using the scan ID
def get_urlscan_report(scan_id):
    report_url = f"https://urlscan.io/api/v1/result/{scan_id}/"
    response = requests.get(report_url, headers=URLSCAN_HEADERS)

    if response.status_code != 200:
        return {"error": f"Failed to retrieve URLScan.io report - {response.status_code}: {response.text}"}

    data = response.json()
    #print(json.dumps(data, indent=4))
    return {
        #"url": data.get("page", {}).get("url"),
        "urlscan: status": data.get("task", {}).get("status"),
        "urlscan: score": data.get("verdicts", {}).get("urlscan", "Unknown"),
        "urlscan: ip stats": data.get("stats", {}).get("ipStats", {}),
        "urlscan: domain": data.get("stats", {}).get("domainStats", {}),
        "urlscan: categories": data.get("verdicts", {}).get("categories", []),
        "urlscan: tags": data.get("verdicts", {}).get("overall", {}).get("tags", []),
        "urlscan: malicious": data.get("verdicts", {}).get("overall", {}).get("malicious", False),
        "urlscan: screenshot url": data.get("task", {}).get("screenshotURL", "N/A"),
        "urlscan: permalink": f"https://urlscan.io/result/{scan_id}/"
    }

# Function to submit a URL to URLScan.io and retrieve the analysis results
def submit_and_query_urlscan(url):
    submission = submit_urlscan(url)
    
    if "error" in submission:
        return submission

    scan_id = submission.get("scan_id")
    time.sleep(30)  # Wait for URLScan.io to process the request

    report = get_urlscan_report(scan_id)
    return report

# Function to query AbuseIPDB for an IP address
def query_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=ABUSEIPDB_HEADERS, params=params)
    if response.status_code == 200:
        data = response.json()
        print(json.dumps(data, indent=4))
        return {
            "abuseipdb: abuse_confidence": data.get("data", {}).get("abuseConfidenceScore", 0),
            "abuseipdb: total_reports": data.get("data", {}).get("totalReports", 0),
            "abuseipdb: country": data.get("data", {}).get("countryCode", "Unknown"),
            "abuseipdb: usage_type": data.get("data", {}).get("usageType", "Unknown"),
            "abuseipdb: isp": data.get("data", {}).get("isp", "Unknown"),
            "abuseipdb: domain": data.get("data", {}).get("domain", "Unknown"),
            "abuseipdb: hostnames": data.get("data", {}).get("hostnames", []),
            "abuseipdb: last_report": data.get("data", {}).get("lastReportedAt", "Unknown"),
            "abuseipdb: is_public": data.get("data", {}).get("isPublic", "Unknown"),
            "abuseipdb: isTor": data.get("data", {}).get("isTor", "Unknown"),
            "abuseipdb: isProxy": data.get("data", {}).get("isProxy", "Unknown")
        }
    else:
        return {"ip": ip, "error": f"Failed to retrieve from AbuseIPDB - Status Code: {response.status_code}, Message: {response.text}"}
    
# Function to query Hybrid Analysis for a file hash
def query_hybrid_analysis_hash(file_hash):
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    payload = f"hash={file_hash}"
    response = requests.post(url, headers=HYBRID_ANALYSIS_HEADERS, data=payload)
    if response.status_code == 200:
        data = response.json()
        if data and isinstance(data, list):
            filtered_data = [x for x in data if x.get("threat_score") is not None]
            if filtered_data:
                best_result = max(filtered_data, key=lambda x: x.get("threat_score", 0))
                #print(json.dumps(data, indent=4))
                return {
                    "hybrid analysis: score": best_result.get("threat_score", "Unknown"),
                    "hybrid analysis: verdict": best_result.get("verdict", "Unknown"),
                    "hybrid analysis: url": best_result.get("report_url", "N/A")
                }
            else:
                return {"hash": file_hash, "hybrid_analysis": "No results with threat score available"}
        else:
            return {"hash": file_hash, "hybrid_analysis": "No results found"}
    elif response.status_code == 404:
        return {"hash": file_hash, "hybrid_analysis": "No results found in Hybrid Analysis"}
    else:
        return {"hash": file_hash, "error": f"Failed to retrieve from Hybrid Analysis - Status Code: {response.status_code}, Message: {response.text}"}

# Main function that processes IOCs
def main():
    while True:
        ioc = input("\nEnter an IOC (IP, domain, hash, email) or type 'exit' to quit: ")
        if ioc.lower() == "exit":
            print("Exiting...")
            break

        ioc_type = determine_ioc_type(ioc)
        result = {"input": ioc, "type": ioc_type}
        
        if ioc_type in ["ipv4", "ipv6"]:
            print(f"\nGathering Intel for IP: {ioc}\n")
            result.update(query_virustotal_ip(ioc))
            result.update(query_abuseipdb(ioc))
            print(json.dumps(result, indent=4))
        elif ioc_type == "domain":
            print(f"\nGathering Intel for Domain: {ioc}\n")
            result.update(query_virustotal_domain(ioc))
            print(json.dumps(result, indent=4))
        elif ioc_type == "url":
            print(f"\nGathering Intel for URL: {ioc}\n")
            print("Please wait while the URL is being scanned...\n")
            result.update(query_virustotal_url(ioc))
            result.update(submit_and_query_urlscan(ioc))
            print(json.dumps(result, indent=4))
        elif ioc_type in ["md5", "sha1", "sha256"]:
            print(f"\nGathering Intel for Hash ({ioc_type.upper()}): {ioc}\n")
            result.update(query_virustotal_hash(ioc))
            result.update(query_hybrid_analysis_hash(ioc))
            print(json.dumps(result, indent=4))
        elif ioc_type == "email":
            print(f"\nGathering Intel for Email: {ioc}\n")
            print(json.dumps(result, indent=4))
        else:
            print("Unknown IOC type. Please enter a valid IP, domain, hash, or email.")

if __name__ == "__main__":
    main()