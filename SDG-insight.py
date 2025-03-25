import requests # Add this import for HTTP requests
import time # Add this import for sleep
import json # Add this import for JSON parsing
import socket # Add this import for WHOIS lookups
import whois # Add this import for WHOIS lookups
import re # Add this import for regular expressions
from urllib.parse import urlparse # Add this import for URL parsing
import validators # Add this import for IOC validation
import base64 # Add this import for URL encoding
import urllib.parse # Add this import for URL encoding
import os # Add this import for loading API keys from a .env file
from dotenv import load_dotenv # Add this import for loading API keys from a .env file
import concurrent.futures # Add this import for threading
import logging # Add this import for logging
from tabulate import tabulate # Add this import for formatting results as a table
import pyperclip   # Add this import for copying results to clipboard
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

# Load environment variables from the .env file
load_dotenv()

# Retrieve API keys from environment variables
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")
IPINFO_API_KEY = os.getenv("IPINFO_API_KEY")
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")
HIBP_API_KEY = os.getenv("HIBP_API_KEY")

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

# Function to display the tool banner
def display_banner():
    banner = r"""

          ____  ____   ____      ___ _   _ ____ ___ ____ _   _ _____ 
         / ___||  _ \ / ___|    |_ _| \ | / ___|_ _/ ___| | | |_   _|
         \___ \| | | | |  _ _____| ||  \| \___ \| | |  _| |_| | | |  
          ___) | |_| | |_| |_____| || |\  |___) | | |_| |  _  | | |  
         |____/|____/ \____|    |___|_| \_|____/___\____|_| |_| |_|  
                                                             
      
                  SOC Analyst All-in-One Investigation Tool
          ------------------------------------------------------------
          - OSINT | Threat Intelligence | Incident Response
          - Integrated APIs: VirusTotal, URLScan, AbuseIP DB and more!
          - Developed for fast and efficient IOC analysis
          ------------------------------------------------------------
     """
    print(banner)

# Function to determine the type of IOC    
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
    
    # Function to perform a WHOIS lookup
def query_whois(ioc, ioc_type):
    try:
        if ioc_type in ["Domain", "URL"]:
            # Extract domain from URL if necessary
            domain = ioc if ioc_type == "Domain" else urlparse(ioc).netloc
            whois_data = whois.whois(domain)
            return {
                "WHOIS: domain_name": whois_data.get("domain_name", "Unknown"),
                "WHOIS: registrar": whois_data.get("registrar", "Unknown"),
                "WHOIS: creation_date": whois_data.get("creation_date", "Unknown"),
                "WHOIS: expiration_date": whois_data.get("expiration_date", "Unknown"),
                "WHOIS: updated_date": whois_data.get("updated_date", "Unknown"),
                "WHOIS: name_servers": whois_data.get("name_servers", []),
                "WHOIS: status": whois_data.get("status", "Unknown"),
            }
        elif ioc_type in ["IPv4", "IPv6"]:
            # Perform IP WHOIS lookup using socket
            whois_data = socket.gethostbyaddr(ioc)
            return {
                "WHOIS: ip_address": ioc,
                "WHOIS: hostname": whois_data[0],
                "WHOIS: aliases": whois_data[1],
                "WHOIS: ip_addresses": whois_data[2],
            }
        else:
            return {"WHOIS: error": "WHOIS lookup is not supported for this IOC type"}
    except Exception as e:
        return {"WHOIS: error": str(e)}
    
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
            return {"HIBP: result": "No breaches found"}
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

        return {"HIBP: breaches": breach_list}

    except requests.RequestException as e:
        return {"HIBP: error": str(e)}


# Function to query ThreatFox for threat intelligence
def query_threatfox(ioc): # Add this function to query ThreatFox for threat intelligence
    url = "https://threatfox-api.abuse.ch/api/v1/" # ThreatFox API URL
    headers = { # Headers for the ThreatFox API
        "Content-Type": "application/json",
        "Auth-Key": THREATFOX_API_KEY
    }

    payload = { # Payload for the ThreatFox API
        "query": "search_ioc",
        "search_term": ioc,
        "exact_match": True
    }

    try: # Try to send a POST request to the ThreatFox API
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        
        # Check if the query was successful and if data was returned
        if data.get("query_status") != "ok" or not data.get("data"):
            return {"Threatfox: result": "No IOC match found"}

        # Extract the top result from the data
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
    
    # Handle any exceptions that occur during the request
    except requests.RequestException as e:
        return {"threatfox: error": str(e)}

# Function to format results as a table using the tabulate library
def format_results_as_table(results): # Add this function to format results as a table
    def format_value(value, indent=0): # Add a nested function to format values
        if isinstance(value, dict): # Check if the value is a dictionary
            # Format dictionaries with indentation
            formatted_dict = [] # List to store formatted dictionary items
            for k, v in value.items(): # Iterate over the dictionary items
                # Recursively format nested dictionaries
                formatted_dict.append(f"{' ' * indent}{k}: {format_value(v, indent + 2)}")
            return '\n'.join(formatted_dict) # Join the formatted items with newlines
        elif isinstance(value, list): # Check if the value is a list
            # Special handling for HIBP breaches
            if "hibp: breaches" in results and value == results["hibp: breaches"]:
                formatted_breaches = [] # List to store formatted breach details
                for breach in value: # Iterate over the breach details
                    # Decode HTML entities and strip HTML tags from the description
                    description = breach.get('Description', 'No description') # Get the description
                    description = html.unescape(description)  # Decode HTML entities
                    description = re.sub(r'<[^>]+>', '', description)  # Remove HTML tags
                    description = textwrap.fill(description, width=80)  # Wrap text to 80 characters
                    description = textwrap.indent(description, ' ' * (indent + 2))  # Indent wrapped lines
                    # Format the breach details
                    formatted_breaches.append( # Append the formatted breach details
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
    
    # Create a table from the results dictionary
    table = []
    for key, value in results.items():
        # Skip entries where the value contains "error"
        if isinstance(value, str) and "error" in value.lower():
            continue
        # Split the key into tool and field    
        if ": " in key: # Check if the key contains ": "
            tool, field = key.split(": ", 1) # Split the key at ": "
        else:
            tool, field = "Insight-OSINT", key

        # Format the value without splitting lists
        formatted_value = format_value(value)
        table.append([tool, field, formatted_value])

    return tabulate(table, headers=["OSINT Source", "Attribute", "Details"], tablefmt="plain")

# Main function that processes IOCs
def main():
    while True:
        ioc = input("\nEnter an IOC (IP, domain, hash, email) or type 'exit' to quit: ")
        if ioc.lower() == "exit":
            print("Exiting...")
            break

        # Determine the type of IOC
        ioc = ioc.strip() # Strip leading/trailing whitespace
        #ioc = ioc.lower() # Convert to lowercase
        ioc_type = determine_ioc_type(ioc)
        result = {"Input": ioc, "Input Type": ioc_type}
        
        # Perform queries based on the IOC type
        with concurrent.futures.ThreadPoolExecutor() as executor: # Use threads for concurrent API queries
            futures = [] # List to store futures for each API query
            
            if ioc_type in ["IPv4", "IPv6"]:
                print(f"\nGathering Intel for IP {ioc}\n")
                futures.append(executor.submit(query_virustotal_ip, ioc))
                futures.append(executor.submit(query_abuseipdb, ioc))
                futures.append(executor.submit(query_shodan, ioc))
                futures.append(executor.submit(query_alienvault_ip, ioc, ioc_type))
                futures.append(executor.submit(query_greynoise, ioc))
                futures.append(executor.submit(query_ipinfo, ioc))
                futures.append(executor.submit(query_threatfox, ioc))
                futures.append(executor.submit(query_whois, ioc, ioc_type))
            elif ioc_type == "Domain":
                print(f"\nGathering Intel for domain {ioc}\n")
                futures.append(executor.submit(query_virustotal_domain, ioc))
                futures.append(executor.submit(query_alienvault_domain, ioc))
                futures.append(executor.submit(query_threatfox, ioc))
                futures.append(executor.submit(query_whois, ioc, ioc_type))
            elif ioc_type == "URL":
                print(f"\nGathering Intel for URL {ioc}\n")
                print("Please wait while the URL is being scanned...\n")
                futures.append(executor.submit(query_virustotal_url, ioc))
                futures.append(executor.submit(submit_and_query_urlscan, ioc))
                futures.append(executor.submit(query_threatfox, ioc))
                futures.append(executor.submit(query_whois, ioc, ioc_type))
            elif ioc_type in ["MD5", "SHA1", "SHA256"]:
                print(f"\nGathering Intel for hash ({ioc_type.upper()}): {ioc}\n")
                futures.append(executor.submit(query_virustotal_hash, ioc))
                futures.append(executor.submit(query_alienvault_hash, ioc))
                futures.append(executor.submit(query_hybrid_analysis_hash, ioc))
                futures.append(executor.submit(query_threatfox, ioc))
            elif ioc_type == "Email":
                print(f"\nGathering Intel for email {ioc}\n")
                futures.append(executor.submit(query_hibp_email, ioc))
                # Add any email-specific queries here if needed
            else:
                print("Unknown IOC type. Please enter a valid IP, domain, hash, or email.")
                continue
            # Wait for all futures to complete
            for future in concurrent.futures.as_completed(futures):
                query_result = future.result()
                result.update(query_result)
                
                # Log successful or failed queries
                for key, value in query_result.items():
                    if "error" in str(value).lower():
                        logging.error(f"Failed query for {key}: {value}")
                    else:
                        logging.info(f"Successful query for {key}: {value}")
            
            # Format and display the results as a table
            formatted_results = format_results_as_table(result)
            print(formatted_results)
            
            # Copy results to clipboard
            pyperclip.copy(formatted_results)
            print("\nResults have been copied to the clipboard.")
            
            # Log final results
            logging.info(f"Final results for IOC {ioc}: {result}")

# Run the main function when the script is executed
if __name__ == "__main__":
    display_banner() # Display the tool banner
    main() # Run the main function