'''
additional packages needed for sdg insight

pip install validators
pip install python-dotenv
pip install tabulate
pip install pyperclip
'''

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
import pyperclip
import html  # Add this import for decoding HTML entities
import re    # Add this import for stripping HTML tags
import textwrap  # Add this import for wrapping text

# Configure logging to write both INFO and ERROR messages to the same file
logging.basicConfig(
    filename='error.log',  # Log file name
    level=logging.INFO,  # Log all messages of level INFO and above
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
    datefmt='%Y-%m-%d %H:%M:%S'  # Date format
)

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
GREYNOISE_API_KEY= "0QzTcyXH5V2DycaLC5LVfYH4At1EXGDVIgLF6mOFZWXJMamiymDVs7NcAzCzguV7"
IPINFO_API_KEY= "25e8915b17234a"
THREATFOX_API_KEY= "bd86ca0e69e3deb541b7283bdc2eede881fad48a4a7a205b"
HIBP_API_KEY= "9cceaed6583144ca94486ac0e677797f"


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
    "API-Key": URLSCAN_API_KEY.strip(),  # Ensure no extra spaces, 
    "Content-Type": "application/json"
}
ALIENVAULT_HEADERS = {
    "X-OTX-API-KEY": ALIENVAULT_API_KEY
}
GREYNOISE_HEADERS = {
    "Accept": "application/json",
    "key": GREYNOISE_API_KEY
}
IPINFO_HEADERS = {
    "Authorization": f"Bearer {IPINFO_API_KEY}"
}
THREATFOX_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Auth-Key": THREATFOX_API_KEY
}
HIBP_HEADERS = {
    "hibp-api-key": HIBP_API_KEY,
    "User-Agent": "SOC-Investigator-Script/1.0"
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
         ------------------------------------------------------------
         - OSINT | Threat Intelligence | Incident Response
         - Integrated APIs: VirusTotal, URLScan, AbuseIP DB and more!
         - Developed for fast and efficient IOC analysis
         ------------------------------------------------------------
     """
    print(banner)
    
def determine_ioc_type(ioc):
    if validators.ipv4(ioc):
        return "IPv4"
    elif validators.ipv6(ioc):
        return "IPv6"
    elif validators.domain(ioc):
        return "Domain"
    elif validators.url(ioc):
        return "URL"
    elif re.fullmatch(r"^[a-fA-F0-9]{32}$", ioc):
        return "MD5"
    elif re.fullmatch(r"^[a-fA-F0-9]{40}$", ioc):
        return "SHA1"
    elif re.fullmatch(r"^[a-fA-F0-9]{64}$", ioc):
        return "SHA256"
    elif validators.email(ioc):
        return "Email"
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
        logging.info(f"Successful API request: {url}")
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
        "Alienvault OTX: pulse_count": data.get("pulse_info", {}).get("count", 0),
        "Alienvault OTX: tags": tags,
        "Alienvault OTX: name": names,
        "Alienvault OTX: permalink": f"https://otx.alienvault.com/indicator/ip/{ioc}"
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
        "Alienvault OTX: pulse_count": data.get("pulse_info", {}).get("count", 0),
        "Alienvault OTX: tags": tags,
        "Alienvault OTX: name": names,
        "Alienvault OTX: permalink": f"https://otx.alienvault.com/indicator/domain/{ioc}"
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
        "Alienvault OTX: pulse_count": data.get("pulse_info", {}).get("count", 0),
        "Alienvault OTX: tags": tags,
        "Alienvault OTX: name": names,
        "Alienvault OTX: permalink": f"https://otx.alienvault.com/indicator/file/{ioc}"
    }

# Function to query VirusTotal for a URL
def query_virustotal_url(url):
    submit_url = "https://www.virustotal.com/api/v3/urls"
    # Encode the URL in base64 format as required by VirusTotal
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
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
    permalink = f"https://www.virustotal.com/gui/url/{encoded_url}"  # Construct the permalink
    return {
        "VirusTotal: reputation": report_data.get("stats", {}),
        "VirusTotal: malicious_vote": report_data.get("votes", {}).get("malicious", 0),
        "VirusTotal: harmless_vote": report_data.get("votes", {}).get("harmless", 0),
        "VirusTotal: permalink": permalink
    }

# Function to query VirusTotal for an IP address
def query_virustotal_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = query_api(url, VT_HEADERS)
    if "error" in response:
        return response

    data = response.get("data", {}).get("attributes", {})
    permalink = f"https://www.virustotal.com/gui/ip-address/{ip}"  # Construct the permalink
    return {
        "VirusTotal: country": data.get("country", "Unknown"),
        "VirusTotal: as_owner": data.get("as_owner", "Unknown"),
        "VirusTotal: reputation": data.get("last_analysis_stats", {}),
        "VirusTotal: malicious_vote": data.get("total_votes", {}).get("malicious", 0),
        "VirusTotal: harmless_vote": data.get("total_votes", {}).get("harmless", 0),
        "VirusTotal: tags": data.get("tags", []),
        "VirusTotal: permalink": permalink
    }

# Function to query VirusTotal for a file hash
def query_virustotal_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = query_api(url, VT_HEADERS)
    if "error" in response:
        return response

    data = response.get("data", {}).get("attributes", {})
    permalink = f"https://www.virustotal.com/gui/file/{file_hash}"  # Construct the permalink
    return {
        "VirusTotal: reputation": data.get("last_analysis_stats", {}),
        "VirusTotal: malicious_vote": data.get("total_votes", {}).get("malicious", 0),
        "VirusTotal: harmless_vote": data.get("total_votes", {}).get("harmless", 0),
        "VirusTotal: tags": data.get("tags", []),
        "VirusTotal: permalink": permalink
    }

# Function to query VirusTotal for a domain
def query_virustotal_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    response = query_api(url, VT_HEADERS)
    if "error" in response:
        return response

    data = response.get("data", {}).get("attributes", {})
    permalink = f"https://www.virustotal.com/gui/domain/{domain}"  # Construct the permalink
    return {
        "VirusTotal: categories": data.get("categories", "Unknown"),
        "VirusTotal: registrar": data.get("registrar", "Unknown"),
        "VirusTotal: reputation": data.get("last_analysis_stats", {}),
        "VirusTotal: malicious_vote": data.get("total_votes", {}).get("malicious", 0),
        "VirusTotal: harmless_vote": data.get("total_votes", {}).get("harmless", 0),
        "VirusTotal: tags": data.get("tags", []),
        "VirusTotal: permalink": permalink
    }

# Function to submit a URL to URLScan.io and retrieve the report
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

# Function to retrieve the URLScan.io report for a given scan ID
def get_urlscan_report(scan_id):
    report_url = f"https://urlscan.io/api/v1/result/{scan_id}/"
    response = query_api(report_url, URLSCAN_HEADERS)
    if "error" in response:
        return response

    data = response
    return {
        "URLscan.io: score": data.get("verdicts", {}).get("urlscan", "Unknown"),
        "URLscan.io: ip stats": data.get("stats", {}).get("ipStats", {}),
        "URLscan.io: domain": data.get("stats", {}).get("domainStats", {}),
        "URLscan.io: categories": data.get("verdicts", {}).get("categories", []),
        "URLscan.io: tags": data.get("verdicts", {}).get("overall", {}).get("tags", []),
        "URLscan.io: malicious": data.get("verdicts", {}).get("overall", {}).get("malicious", False),
        "URLscan.io: screenshot url": data.get("task", {}).get("screenshotURL", "N/A"),
        "URLscan.io: permalink": f"https://urlscan.io/result/{scan_id}/"
    }

# Function to submit a URL to URLScan.io and retrieve the report
def submit_and_query_urlscan(url):
    submission = submit_urlscan(url)
    if "error" in submission:
        logging.error(f"Error during URL submission: {submission['error']}")
        return submission

    scan_id = submission.get("scan_id")
    if not scan_id:
        logging.error("Failed to extract scan ID from URLScan.io response")
        return {"error": "Failed to extract scan ID from URLScan.io response"}

    logging.info(f"Scan submitted. Scan ID: {scan_id}. Waiting for the scan to complete...")

    # Retry mechanism to wait for the scan to complete
    max_retries = 10
    retry_delay = 30  # seconds
    for attempt in range(max_retries):
        time.sleep(retry_delay)
        report = get_urlscan_report(scan_id)
        if "error" not in report:
            return report
        if "Scan is not finished yet" in report.get("error", ""):
            logging.info(f"Attempt {attempt + 1}/{max_retries}: Scan is not finished yet. Retrying in {retry_delay} seconds...")
        else:
            logging.error(f"Error retrieving report: {report['error']}")
            return report

    logging.error("Failed to retrieve URLScan.io report after multiple attempts")
    return {"error": "Failed to retrieve URLScan.io report after multiple attempts"}

# Function to query AbuseIPDB for an IP address
def query_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = query_api(url, ABUSEIPDB_HEADERS, params=params)
    if "error" in response:
        return response

    data = response.get("data", {})
    return {
        "AbuseIPDB: abuse_confidence": data.get("abuseConfidenceScore", 0),
        "AbuseIPDB: total_reports": data.get("totalReports", 0),
        "AbuseIPDB: country": data.get("countryCode", "Unknown"),
        "AbuseIPDB: usage_type": data.get("usageType", "Unknown"),
        "AbuseIPDB: isp": data.get("isp", "Unknown"),
        "AbuseIPDB: domain": data.get("domain", "Unknown"),
        "AbuseIPDB: hostnames": data.get("hostnames", []),
        "AbuseIPDB: last_report": data.get("lastReportedAt", "Unknown"),
        "AbuseIPDB: is_public": data.get("isPublic", "Unknown"),
        "AbuseIPDB: isTor": data.get("isTor", "Unknown"),
        "AbuseIPDB: isProxy": data.get("isProxy", "Unknown"),
        "AbuseIPDB: permalink": f"https://www.abuseipdb.com/check/{ip}"  # Add permalink
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
        "Hybrid analysis: threat score": best_result.get("threat_score", "Unknown"),
        "Hybrid analysis: av detect": best_result.get("av_detect", "Unknown"),
        "Hybrid analysis: verdict": best_result.get("verdict", "Unknown"),
        "Hybrid analysis: submissions": best_result.get("submissions", "Unknown"),
        "Hybrid analysis: url": best_result.get("report_url", "N/A")
    }

# Function to query Shodan for IP intelligence
def query_shodan(ip):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    response = query_api(url, {})
    if "error" in response:
        return response

    data = response
    return {
        "Shodan: ip": ip,
        "Shodan: country": data.get("country_name", "Unknown"),
        "Shodan: organization": data.get("org", "Unknown"),
        "Shodan: open_ports": data.get("ports", []),
        "Shodan: vulnerabilities": data.get("vulns", []),
        "Shodan: hostnames": data.get("hostnames", []),
        "Shodan: permalink": f"https://www.shodan.io/host/{ip}"
    }

# Function to query Greynoise for IP intelligence
def query_greynoise(ip):
    url = f"https://api.greynoise.io/v3/community/{ip}"
    response = query_api(url, GREYNOISE_HEADERS)
    
    if "error" in response:
        return {"greynoise: error": response["error"]}

    return {
        "Greynoise: classification": response.get("classification", "unknown"),
        "Greynoise: name": response.get("name", "unknown"),
        "Greynoise: link": f"https://viz.greynoise.io/ip/{ip}",
        "Greynoise: last_seen": response.get("last_seen", "unknown"),
        "Greynoise: actor": response.get("actor", "unknown"),
        "Greynoise: tags": response.get("tags", []),
        "Greynoise: riot": response.get("riot", {}),
        "Greynoise: message": response.get("message", {}),
        "Greynoise: metadata": response.get("metadata", {})
    }

# Function to query IPinfo for IP intelligence
def query_ipinfo(ip):
    url = f"https://ipinfo.io/{ip}/json"
    response = query_api(url, IPINFO_HEADERS)

    if "error" in response:
        return {"ipinfo: error": response["error"]}

    return {
        "IPinfo: ip": response.get("ip", "unknown"),
        "IPinfo: city": response.get("city", "unknown"),
        "IPinfo: region": response.get("region", "unknown"),
        "IPinfo: country": response.get("country", "unknown"),
        "IPinfo: location": response.get("loc", "unknown"),
        "IPinfo: org": response.get("org", "unknown"),
        "IPinfo: asn": response.get("asn", {}).get("asn", "unknown") if isinstance(response.get("asn"), dict) else "unknown",
        "IPinfo: privacy": response.get("privacy", {}),
        "IPinfo: abuse_contact": response.get("abuse", {}).get("address", "unknown"),
        "IPinfo: link": f"https://ipinfo.io/{ip}"
    }

# Function to query Have I Been Pwned for email breaches
def query_hibp_email(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"

    try:
        response = requests.get(url, headers=HIBP_HEADERS)
        if response.status_code == 404:
            return {"hibp: result": "No breaches found"}
        response.raise_for_status()
        breaches = response.json()

        breach_list = []
        for breach in breaches:
            breach_list.append({
                "Name": breach.get("Name", "Unknown"),
                "BreachDate": breach.get("BreachDate", "Unknown"),
                "Description": breach.get("Description", "No description"),
                "DataClasses": breach.get("DataClasses", [])
            })

        return {"hibp: breaches": breach_list}

    except requests.RequestException as e:
        return {"hibp: error": str(e)}


# Function to query ThreatFox for threat intelligence
def query_threatfox(ioc):
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {
        "Content-Type": "application/json",
        "Auth-Key": THREATFOX_API_KEY
    }

    payload = {
        "query": "search_ioc",
        "search_term": ioc,
        "exact_match": True
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()

        if data.get("query_status") != "ok" or not data.get("data"):
            return {"threatfox: result": "No IOC match found"}

        top = data["data"][0]
        return {
            "Threatfox: ioc_type": top.get("ioc_type_desc", "Unknown"),
            "Threatfox: threat_type": top.get("threat_type_desc", "Unknown"),
            "Threatfox: malware": top.get("malware_printable", top.get("malware", "Unknown")),
            "Threatfox: confidence": top.get("confidence_level", "Unknown"),
            "Threatfox: first_seen": top.get("first_seen", "Unknown"),
            "Threatfox: last_seen": top.get("last_seen", "Unknown"),
            "Threatfox: reference": top.get("reference", "N/A"),
            "Threatfox: tags": top.get("tags", []),
            "Threatfox: malpedia": top.get("malware_malpedia", None)
        }

    except requests.RequestException as e:
        return {"threatfox: error": str(e)}

# Function to format results as a table using the tabulate library
def format_results_as_table(results):
    def format_value(value, indent=0):
        if isinstance(value, dict):
            formatted_dict = []
            for k, v in value.items():
                formatted_dict.append(f"{' ' * indent}{k}: {format_value(v, indent + 2)}")
            return '\n'.join(formatted_dict)
        elif isinstance(value, list):
            # Special handling for HIBP breaches
            if "hibp: breaches" in results and value == results["hibp: breaches"]:
                formatted_breaches = []
                for breach in value:
                    # Decode HTML entities and strip HTML tags from the description
                    description = breach.get('Description', 'No description')
                    description = html.unescape(description)  # Decode HTML entities
                    description = re.sub(r'<[^>]+>', '', description)  # Remove HTML tags
                    description = textwrap.fill(description, width=80)  # Wrap text to 80 characters
                    description = textwrap.indent(description, ' ' * (indent + 2))  # Indent wrapped lines

                    formatted_breaches.append(
                        f"{' ' * indent}Name: {breach.get('Name', 'Unknown')}\n"
                        f"{' ' * (indent + 2)}Breach Date: {breach.get('BreachDate', 'Unknown')}\n"
                        f"{' ' * (indent + 2)}Description: {description}\n"
                        f"{' ' * (indent + 2)}Data Exposed: {', '.join(breach.get('DataClasses', []))}\n"
                    )
                return '\n'.join(formatted_breaches)
            else:
                # Format other lists
                filtered_values = [item for item in value if item]
                if not filtered_values:
                    return "N/A"  # Return "N/A" if the list is empty
                unique_values = list(dict.fromkeys(map(str, filtered_values)))  # Remove duplicates while preserving order
                formatted_list = [f"{' ' * indent}- {item}" for item in unique_values]
                return '\n'.join(formatted_list)  # Join the list items with newlines
        elif value in [None, ""]:
            return "N/A"  # Return "N/A" for empty or None values
        return str(value)

    table = []
    for key, value in results.items():
        # Skip entries where the value contains "error"
        if isinstance(value, str) and "error" in value.lower():
            continue

        if ": " in key:
            tool, field = key.split(": ", 1)
        else:
            tool, field = "Insight-OSINT", key

        # Format the value without splitting lists
        formatted_value = format_value(value)
        table.append([tool, field, formatted_value])

    return tabulate(table, headers=["Source", "Attribute", "Details"], tablefmt="plain")

# Main function that processes IOCs
def main():
    while True:
        ioc = input("\nEnter an IOC (IP, domain, hash, email) or type 'exit' to quit: ")
        if ioc.lower() == "exit":
            print("Exiting...")
            break

        # Determine the type of IOC
        ioc = ioc.strip()
        ioc_type = determine_ioc_type(ioc)
        result = {"Input": ioc, "Input Type": ioc_type}
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            
            if ioc_type in ["IPv4", "IPv6"]:
                print(f"\nGathering Intel for IP {ioc}\n")
                futures.append(executor.submit(query_virustotal_ip, ioc))
                futures.append(executor.submit(query_abuseipdb, ioc))
                futures.append(executor.submit(query_shodan, ioc))
                futures.append(executor.submit(query_alienvault_ip, ioc, ioc_type))
                futures.append(executor.submit(query_greynoise, ioc))
                futures.append(executor.submit(query_ipinfo, ioc))
                futures.append(executor.submit(query_threatfox, ioc))
            elif ioc_type == "Domain":
                print(f"\nGathering Intel for Domain {ioc}\n")
                futures.append(executor.submit(query_virustotal_domain, ioc))
                futures.append(executor.submit(query_alienvault_domain, ioc))
                futures.append(executor.submit(query_threatfox, ioc))
            elif ioc_type == "URL":
                print(f"\nGathering Intel for URL {ioc}\n")
                print("Please wait while the URL is being scanned...\n")
                futures.append(executor.submit(query_virustotal_url, ioc))
                futures.append(executor.submit(submit_and_query_urlscan, ioc))
                futures.append(executor.submit(query_threatfox, ioc))
            elif ioc_type in ["MD5", "SHA1", "SHA256"]:
                print(f"\nGathering Intel for Hash ({ioc_type.upper()}): {ioc}\n")
                futures.append(executor.submit(query_virustotal_hash, ioc))
                futures.append(executor.submit(query_alienvault_hash, ioc))
                futures.append(executor.submit(query_hybrid_analysis_hash, ioc))
                futures.append(executor.submit(query_threatfox, ioc))
            elif ioc_type == "Email":
                print(f"\nGathering Intel for Email {ioc}\n")
                futures.append(executor.submit(query_hibp_email, ioc))
                # Add any email-specific queries here if needed
            else:
                print("Unknown IOC type. Please enter a valid IP, domain, hash, or email.")
                continue
            
            for future in concurrent.futures.as_completed(futures):
                query_result = future.result()
                result.update(query_result)
                
                # Log successful or failed queries
                for key, value in query_result.items():
                    if "error" in str(value).lower():
                        logging.error(f"Failed query for {key}: {value}")
                    else:
                        logging.info(f"Successful query for {key}: {value}")
            
            formatted_results = format_results_as_table(result)
            print(formatted_results)
            
            # Copy results to clipboard
            pyperclip.copy(formatted_results)
            print("\nResults have been copied to the clipboard.")
            
            logging.info(f"Final results for IOC {ioc}: {result}")

if __name__ == "__main__":
    display_banner()
    main()