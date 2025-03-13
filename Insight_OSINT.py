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


# API Keys (Set your own keys here)
VIRUSTOTAL_API_KEY = "ca1e9b61569e86434c6e5e30345c6a453e51b3f0197148c3d51af895968bd4ba"
ABUSEIPDB_API_KEY = "fb7a1175a449e459010776fea3d4ec2832b647da0422384efbbadc4ad594479f7efb6983dfe522ea"
HYBRID_ANALYSIS_API_KEY = "6rnakmkj6ed49416v459v1fl75bbd7e3abafiwmf99ea95f84ow80g0ce3464a5d"

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
def submit_and_query_url_virustotal(url):
   
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
    # time.sleep(15)  # Give VirusTotal time to analyze the URL

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
        "URL": url,
        "Virus Total Scan Status": report_data["data"]["attributes"]["status"],
        "Virus Total Reputation Stats": report_data["data"]["attributes"]["stats"],
        #"tags": analysis_attributes.get("tags", []),
        #"VT permalink": f"https://www.virustotal.com/gui/url/{scan_id}"
    }

    # Function to query VirusTotal for an IP address
def query_virustotal_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(url, headers=VT_HEADERS)
    if response.status_code == 200:
        data = response.json()
        print(json.dumps(data, indent=4))
        return {
            "ip": ip,
            "vt_country": data.get("data", {}).get("attributes", {}).get("country", "Unknown"),
            "vt_reputation": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
            "vt_malicious": data.get("data", {}).get("attributes", {}).get("total_votes", {}).get("malicious", 0),
            "vt_harmless": data.get("data", {}).get("attributes", {}).get("total_votes", {}).get("harmless", 0),
            "vt_tags": data.get("data", {}).get("attributes", {}).get("tags", [])
        }
    else:
        return {"ip": ip, "error": f"Failed to retrieve from VirusTotal - Status Code: {response.status_code}, Message: {response.text}"}

# Function to query VirusTotal for a file hash
def query_virustotal_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(url, headers=VT_HEADERS)
    if response.status_code == 200:
        data = response.json()
        print(json.dumps(data, indent=4))
        return {
            "hash": file_hash,
            "vt_reputation": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
            "vt_malicious": data.get("data", {}).get("attributes", {}).get("total_votes", {}).get("malicious", 0),
            "vt_harmless": data.get("data", {}).get("attributes", {}).get("total_votes", {}).get("harmless", 0)
        }
    else:
        return {"hash": file_hash, "error": f"Failed to retrieve from VirusTotal - Status Code: {response.status_code}, Message: {response.text}"}

# Function to query VirusTotal for a domain
def query_virustotal_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    response = requests.get(url, headers=VT_HEADERS)
    if response.status_code == 200:
        data = response.json()
        return {
            "domain": domain,
            "vt_reputation": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
            "vt_malicious": data.get("data", {}).get("attributes", {}).get("total_votes", {}).get("malicious", 0),
            "vt_harmless": data.get("data", {}).get("attributes", {}).get("total_votes", {}).get("harmless", 0)
        }
    else:
        return {"domain": domain, "error": f"Failed to retrieve from VirusTotal - Status Code: {response.status_code}, Message: {response.text}"}
    
# Function to query VirusTotal for a URL
def query_virustotal_url(url):
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url}"
    response = requests.post(vt_url, headers=VT_HEADERS)
    if response.status_code == 200:
        data = response.json()
        return {
            "url": url,
            "vt_reputation": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
            "vt_malicious": data.get("data", {}).get("attributes", {}).get("total_votes", {}).get("malicious", 0),
            "vt_harmless": data.get("data", {}).get("attributes", {}).get("total_votes", {}).get("harmless", 0)
        }
    else:
        return {
            "url": url,
            "error": f"Failed to retrieve from VirusTotal - Status Code: {response.status_code}, Message: {response.text}"
        }
    
    # Function to query AbuseIPDB for an IP address
def query_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=ABUSEIPDB_HEADERS, params=params)
    if response.status_code == 200:
        data = response.json()
        return {
            "ip": ip,
            "abuse_confidence": data.get("data", {}).get("abuseConfidenceScore", 0),
            "total_reports": data.get("data", {}).get("totalReports", 0),
            "country": data.get("data", {}).get("countryCode", "Unknown"),
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
                return {
                    "hash": file_hash,
                    "hybrid_analysis_score": best_result.get("threat_score", "Unknown"),
                    "hybrid_analysis_verdict": best_result.get("verdict", "Unknown"),
                    "hybrid_analysis_url": best_result.get("report_url", "N/A")
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
        ioc = input("Enter an IOC (IP, domain, hash, email) or type 'exit' to quit: ")
        if ioc.lower() == "exit":
            print("Exiting...")
            break
        
        ioc_type = determine_ioc_type(ioc)
        result = {"input": ioc, "type": ioc_type}
        
        if ioc_type in ["ipv4", "ipv6"]:
            print(f"Processing IP: {ioc}")
            result.update(query_virustotal_ip(ioc))
            result.update(query_abuseipdb(ioc))
            print(json.dumps(result, indent=4))
        elif ioc_type == "domain":
            print(f"Processing Domain: {ioc}")
            result.update(query_virustotal_domain(ioc))
            print(json.dumps(result, indent=4))
        elif ioc_type == "url":
            print(f"Processing URL: {ioc}")
            result.update(submit_and_query_url_virustotal(ioc))
            print(json.dumps(result, indent=4))
        elif ioc_type in ["md5", "sha1", "sha256"]:
            print(f"Processing Hash ({ioc_type.upper()}): {ioc}")
            result.update(query_virustotal_hash(ioc))
            result.update(query_hybrid_analysis_hash(ioc))
            print(json.dumps(result, indent=4))
        elif ioc_type == "email":
            print(f"Processing Email: {ioc}")
            print(json.dumps(result, indent=4))
        else:
            print("Unknown IOC type. Please enter a valid IP, domain, hash, or email.")

if __name__ == "__main__":
    main()