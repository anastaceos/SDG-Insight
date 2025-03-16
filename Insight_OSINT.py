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
import concurrent.futures
import logging
from tabulate import tabulate

#load_dotenv()  # Load API keys from a .env file

#VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
#ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")http
#HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")

# API Keys (Set your own keys here)
VIRUSTOTAL_API_KEY = "ca1e9b61569e86434c6e5e30345c6a453e51b3f0197148c3d51af895968bd4ba"
ABUSEIPDB_API_KEY = "fb7a1175a449e459010776fea3d4ec2832b647da0422384efbbadc4ad594479f7efb6983dfe522ea"
HYBRID_ANALYSIS_API_KEY = "6rnakmkj6ed49416v459v1fl75bbd7e3abafiwmf99ea95f84ow80g0ce3464a5d"
URLSCAN_API_KEY = "01958a4b-1aec-7001-9c07-e01053a8158b"
SHODAN_API_KEY = "Pc0gdLR5F1JXVSPLRDazU6u50YMjbUNW"
ALIENVAULT_API_KEY = "b1a72dbeaa5f0991bc9d57f4ed64234341cb015a15c205a02a0d440bf2079418"

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
    "API-Key": URLSCAN_API_KEY, 
    "Content-Type": "application/json"
}
ALIENVAULT_HEADERS = {
    "X-OTX-API-KEY": ALIENVAULT_API_KEY
}
    
def determine_ioc_type(ioc):
    if validators.ipv4(ioc):
        return "IPv4"
    elif validators.ipv6(ioc):
        return "IPv6"
    elif validators.domain(ioc):
        return "Domain"
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
    
# Function to query an API with the given URL and headers    
def query_api(url, headers, params=None, data=None, method="GET"):
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, params=params)
        elif method == "POST":
            response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error(f"API request failed: {e}")
        return {"error": str(e)}
    
# Function to query AlienVault OTX for an IP address  
def query_alienvault_ip(ioc, ioc_type):
    url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc}/general"

    response = query_api(url, ALIENVAULT_HEADERS)
    if "error" in response:
        return response

    data = response
    #print(json.dumps(data, indent=4))
    tags = [tag for pulse in data.get("pulse_info", {}).get("pulses", []) for tag in pulse.get("tags", [])]
    names = [pulse.get("name", "Unknown") for pulse in data.get("pulse_info", {}).get("pulses", [])]
    return {
        "alienvault: pulse_count": data.get("pulse_info", {}).get("count", 0),
        "alienvault: tags": tags,
        "alienvault: name": names,
        "alienvault: permalink": f"https://otx.alienvault.com/indicator/{ioc_type}/{ioc}"
    }

# Function to query AlienVault OTX for a domain
def query_alienvault_domain(ioc):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}"

    response = query_api(url, ALIENVAULT_HEADERS)
    if "error" in response:
        return response

    data = response
    #print(json.dumps(data, indent=4))
    tags = [tag for pulse in data.get("pulse_info", {}).get("pulses", []) for tag in pulse.get("tags", [])]
    names = [pulse.get("name", "Unknown") for pulse in data.get("pulse_info", {}).get("pulses", [])]
    return {
        "alienvault: pulse_count": data.get("pulse_info", {}).get("count", 0),
        "alienvault: tags": tags,
        "alienvault: name": names,
        "alienvault: permalink": f"https://otx.alienvault.com/indicator/domain/{ioc}"
    }

# Function to query AlienVault OTX for a hash
def query_alienvault_hash(ioc):
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{ioc}"

    response = query_api(url, ALIENVAULT_HEADERS)
    if "error" in response:
        return response

    data = response
    #print(json.dumps(data, indent=4))
    tags = [tag for pulse in data.get("pulse_info", {}).get("pulses", []) for tag in pulse.get("tags", [])]
    names = [pulse.get("name", "Unknown") for pulse in data.get("pulse_info", {}).get("pulses", [])]
    return {
        "alienvault: pulse_count": data.get("pulse_info", {}).get("count", 0),
        "alienvault: tags": tags,
        "alienvault: name": names,
        "alienvault: permalink": f"https://otx.alienvault.com/indicator/file/{ioc}"
    }

# Function to query VirusTotal for a URL
def query_virustotal_url(url):
    submit_url = "https://www.virustotal.com/api/v3/urls"
    response = query_api(submit_url, VT_HEADERS, data={"url": url}, method="POST")
    if "error" in response:
        return response

    scan_id = response.get("data", {}).get("id")
    if not scan_id:
        return {"error": "Failed to extract scan ID from VirusTotal response"}

    time.sleep(60)  # Give VirusTotal time to analyze the URL

    report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    report_response = query_api(report_url, VT_HEADERS)
    if "error" in report_response:
        return report_response

    report_data = report_response.get("data", {}).get("attributes", {})
    #print(json.dumps(report_data, indent=4))
    return {
        #"virustotal: status": report_data.get("status"),
        "virustotal: reputation": report_data.get("stats"),
    }

# Function to query VirusTotal for an IP address
def query_virustotal_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = query_api(url, VT_HEADERS)
    if "error" in response:
        return response

    data = response.get("data", {}).get("attributes", {})
    return {
        "virustotal: country": data.get("country", "Unknown"),
        "virustotal: as_owner": data.get("as_owner", "Unknown"),
        "virustotal: reputation": data.get("last_analysis_stats", {}),
        "virustotal: malicious_vote": data.get("total_votes", {}).get("malicious", 0),
        "virustotal: harmless_vote": data.get("total_votes", {}).get("harmless", 0),
        "virustotal: tags": data.get("tags", [])
    }

# Function to query VirusTotal for a file hash
def query_virustotal_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = query_api(url, VT_HEADERS)
    if "error" in response:
        return response

    data = response.get("data", {}).get("attributes", {})
    return {
        "virustotal: reputation": data.get("last_analysis_stats", {}),
        "virustotal: malicious_vote": data.get("total_votes", {}).get("malicious", 0),
        "virustotal: harmless_vote": data.get("total_votes", {}).get("harmless", 0),
        "virustotal: tags": data.get("tags", [])
    }

# Function to query VirusTotal for a domain
def query_virustotal_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    response = query_api(url, VT_HEADERS)
    if "error" in response:
        return response

    data = response.get("data", {}).get("attributes", {})
    return {
        "virustotal: categories": data.get("categories", "Unknown"),
        "virustotal: registrar": data.get("registrar", "Unknown"),
        "virustotal: reputation": data.get("last_analysis_stats", {}),
        "virustotal: malicious_vote": data.get("total_votes", {}).get("malicious", 0),
        "virustotal: harmless_vote": data.get("total_votes", {}).get("harmless", 0),
        "virustotal: tags": data.get("tags", [])
    }

def submit_urlscan(url):
    submit_url = "https://urlscan.io/api/v1/scan/"
    payload = {"url": url, "visibility": "public"}
    response = query_api(submit_url, URLSCAN_HEADERS, data=json.dumps(payload), method="POST")
    if "error" in response:
        return response

    return {
        "url": url,
        "scan_id": response.get("uuid"),
        "urlscan_permalink": response.get("result")
    }

def get_urlscan_report(scan_id):
    report_url = f"https://urlscan.io/api/v1/result/{scan_id}/"
    response = query_api(report_url, URLSCAN_HEADERS)
    if "error" in response:
        return response

    data = response
    return {
        #"urlscan: status": data.get("task", {}).get("status"),
        "urlscan: score": data.get("verdicts", {}).get("urlscan", "Unknown"),
        "urlscan: ip stats": data.get("stats", {}).get("ipStats", {}),
        "urlscan: domain": data.get("stats", {}).get("domainStats", {}),
        "urlscan: categories": data.get("verdicts", {}).get("categories", []),
        "urlscan: tags": data.get("verdicts", {}).get("overall", {}).get("tags", []),
        "urlscan: malicious": data.get("verdicts", {}).get("overall", {}).get("malicious", False),
        "urlscan: screenshot url": data.get("task", {}).get("screenshotURL", "N/A"),
        "urlscan: permalink": f"https://urlscan.io/result/{scan_id}/"
    }

def submit_and_query_urlscan(url):
    submission = submit_urlscan(url)
    if "error" in submission:
        return submission

    scan_id = submission.get("scan_id")
    time.sleep(60)  # Wait for URLScan.io to process the request

    report = get_urlscan_report(scan_id)
    return report    

# Function to query AbuseIPDB for an IP address
def query_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = query_api(url, ABUSEIPDB_HEADERS, params=params)
    if "error" in response:
        return response

    data = response.get("data", {})
    return {
        "abuseipdb: abuse_confidence": data.get("abuseConfidenceScore", 0),
        "abuseipdb: total_reports": data.get("totalReports", 0),
        "abuseipdb: country": data.get("countryCode", "Unknown"),
        "abuseipdb: usage_type": data.get("usageType", "Unknown"),
        "abuseipdb: isp": data.get("isp", "Unknown"),
        "abuseipdb: domain": data.get("domain", "Unknown"),
        "abuseipdb: hostnames": data.get("hostnames", []),
        "abuseipdb: last_report": data.get("lastReportedAt", "Unknown"),
        "abuseipdb: is_public": data.get("isPublic", "Unknown"),
        "abuseipdb: isTor": data.get("isTor", "Unknown"),
        "abuseipdb: isProxy": data.get("isProxy", "Unknown")
    }

# Function to query Hybrid Analysis for a file hash
def query_hybrid_analysis_hash(file_hash):
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    payload = f"hash={file_hash}"
    response = query_api(url, HYBRID_ANALYSIS_HEADERS, data=payload, method="POST")
    if "error" in response:
        return response

    data = response
    if not data or not isinstance(data, list):
        return {"hash": file_hash, "hybrid_analysis": "No results found"}

    filtered_data = [x for x in data if x.get("threat_score") is not None]
    if not filtered_data:
        return {"hash": file_hash, "hybrid_analysis": "No results with threat score available"}

    best_result = max(filtered_data, key=lambda x: x.get("threat_score", 0))
    return {
        "hybrid analysis: threat score": best_result.get("threat_score", "Unknown"),
        "hybrid analysis: av detect": best_result.get("av_detect", "Unknown"),
        "hybrid analysis: verdict": best_result.get("verdict", "Unknown"),
        "hybrid analysis: submissions": best_result.get("submissions", "Unknown"),
        "hybrid analysis: url": best_result.get("report_url", "N/A")
    }

# Function to query Shodan for IP intelligence
def query_shodan(ip):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    response = query_api(url, {})
    if "error" in response:
        return response

    data = response
    return {
        "shodan: ip": ip,
        "shodan: country": data.get("country_name", "Unknown"),
        "shodan: organization": data.get("org", "Unknown"),
        "shodan: open_ports": data.get("ports", []),
        "shodan: vulnerabilities": data.get("vulns", []),
        "shodan: hostnames": data.get("hostnames", []),
        "shodan: permalink": f"https://www.shodan.io/host/{ip}"
    }

def display_banner():
    banner = r"""
  _____           _       _     _           ____   _____ _____ _   _ _______ 
 |_   _|         (_)     | |   | |         / __ \ / ____|_   _| \ | |__   __|
   | |  _ __  ___ _  __ _| |__ | |_ ______| |  | | (___   | | |  \| |  | |   
   | | | '_ \/ __| |/ _` | '_ \| __|______| |  | |\___ \  | | | . ` |  | |   
  _| |_| | | \__ \ | (_| | | | | |_       | |__| |____) |_| |_| |\  |  | |   
 |_____|_| |_|___/_|\__, |_| |_|\__|       \____/|_____/|_____|_| \_|  |_|   
                     __/ |                                                   
                    |___/                                                                   
            SOC Analyst All-in-One Investigation Tool
          ------------------------------------------------
          - OSINT | Threat Intelligence | Incident Response
          - Integrated APIs: VirusTotal, URLScan, AbuseIP DB and more!
          - Developed for fast and efficient IOC analysis
          ------------------------------------------------
     """
    print(banner)

# Function to format results as a table using the tabulate library
def format_results_as_table(results):
    def split_into_lines(value, length=150):
        if isinstance(value, str) and len(value) > length:
            return '\n'.join([value[i:i+length] for i in range(0, len(value), length)])
        return value

    def format_value(value, indent=0):
        if isinstance(value, dict):
            formatted_dict = []
            for k, v in value.items():
                formatted_dict.append(f"{' ' * indent}{k}: {format_value(v, indent + 2)}")
            return '\n'.join(formatted_dict)
        elif isinstance(value, list):
            unique_values = list(dict.fromkeys(map(str, value)))  # Remove duplicates while preserving order
            formatted_list = [f"{' ' * indent}- {item}" for item in unique_values]
            return '\n'.join(formatted_list)
        return str(value)

    table = []
    for key, value in results.items():
        if ": " in key:
            tool, field = key.split(": ", 1)
        else:
            tool, field = "", key
        formatted_value = format_value(value)
        split_value = split_into_lines(formatted_value)
        table.append([tool, field, split_value])
    return tabulate(table, headers=["Tool", "Field", "Value"], tablefmt="grid")

# Main function that processes IOCs
def main():
    while True:
        ioc = input("\nEnter an IOC (IP, domain, hash, email) or type 'exit' to quit: ")
        if ioc.lower() == "exit":
            print("Exiting...")
            break

        # Determine the type of IOC
        # Strip any leading/trailing whitespace
        ioc = ioc.strip()    
        ioc_type = determine_ioc_type(ioc)
        result = {"input": ioc, "type": ioc_type}
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            
            if ioc_type in ["IPv4", "IPv6"]:
                print(f"\nGathering Intel for IP: {ioc}\n")
                futures.append(executor.submit(query_virustotal_ip, ioc))
                futures.append(executor.submit(query_abuseipdb, ioc))
                futures.append(executor.submit(query_shodan, ioc))
                futures.append(executor.submit(query_alienvault_ip, ioc, ioc_type))
            elif ioc_type == "Domain":
                print(f"\nGathering Intel for Domain: {ioc}\n")
                futures.append(executor.submit(query_virustotal_domain, ioc))
                futures.append(executor.submit(query_alienvault_domain, ioc))
            elif ioc_type == "url":
                print(f"\nGathering Intel for URL: {ioc}\n")
                print("Please wait while the URL is being scanned...\n")
                futures.append(executor.submit(query_virustotal_url, ioc))
                futures.append(executor.submit(submit_and_query_urlscan, ioc))
            elif ioc_type in ["md5", "sha1", "sha256"]:
                print(f"\nGathering Intel for Hash ({ioc_type.upper()}): {ioc}\n")
                futures.append(executor.submit(query_virustotal_hash, ioc))
                futures.append(executor.submit(query_alienvault_hash, ioc))
                futures.append(executor.submit(query_hybrid_analysis_hash, ioc))
            elif ioc_type == "email":
                print(f"\nGathering Intel for Email: {ioc}\n")
                # Add any email-specific queries here if needed
            else:
                print("Unknown IOC type. Please enter a valid IP, domain, hash, or email.")
                continue
            
            for future in concurrent.futures.as_completed(futures):
                result.update(future.result())
            
            #print(json.dumps(result, indent=4))

            print(format_results_as_table(result))

if __name__ == "__main__":
    display_banner()
    main()