import concurrent.futures # Add this import for threading
import logging # Add this import for logging
from tabulate import tabulate # Add this import for formatting results as a table
import pyperclip   # Add this import for copying results to clipboard
from core.banner import display_banner # Import the display_banner function
from core.ioc_detection import determine_ioc_type # Import the determine_ioc_type function
from core.result_formatter import format_results_as_table # Import the format_results_as_table function
from core.utils import setup_logging # Import the setup_logging function
from core.api_handlers import ( # Import the API query functions
    query_virustotal_ip, query_abuseipdb, query_shodan, query_alienvault_ip,
    query_greynoise, query_ipinfo, query_threatfox,
    query_virustotal_domain, query_alienvault_domain, query_virustotal_url,
    submit_and_query_urlscan, query_virustotal_hash, query_alienvault_hash,
    query_hybrid_analysis_hash, query_hibp_email, query_whois
)

# Main function that processes IOCs
def main():

    setup_logging()  # Initialize logging
    display_banner()  # Display the tool banners

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
            
            if ioc_type in ["IPv4", "IPv6"]: # Check if the IOC is an IP address
                print(f"\nGathering Intel for IP {ioc}\n")
                futures.append(executor.submit(query_virustotal_ip, ioc))
                futures.append(executor.submit(query_abuseipdb, ioc))
                futures.append(executor.submit(query_shodan, ioc))
                futures.append(executor.submit(query_alienvault_ip, ioc, ioc_type))
                futures.append(executor.submit(query_greynoise, ioc))
                futures.append(executor.submit(query_ipinfo, ioc))
                futures.append(executor.submit(query_threatfox, ioc))
                futures.append(executor.submit(query_whois, ioc, ioc_type))
            elif ioc_type == "Domain": # Check if the IOC is a domain
                print(f"\nGathering Intel for domain {ioc}\n")
                futures.append(executor.submit(query_virustotal_domain, ioc))
                futures.append(executor.submit(query_alienvault_domain, ioc))
                futures.append(executor.submit(query_threatfox, ioc))
                futures.append(executor.submit(query_whois, ioc, ioc_type))
            elif ioc_type == "URL": # Check if the IOC is a URL
                print(f"\nGathering Intel for URL {ioc}\n")
                print("Please wait while the URL is being scanned...\n")
                futures.append(executor.submit(query_virustotal_url, ioc))
                futures.append(executor.submit(submit_and_query_urlscan, ioc))
                futures.append(executor.submit(query_threatfox, ioc))
                futures.append(executor.submit(query_whois, ioc, ioc_type))
            elif ioc_type in ["MD5", "SHA1", "SHA256"]: # Check if the IOC is a hash
                print(f"\nGathering Intel for hash ({ioc_type.upper()}): {ioc}\n")
                futures.append(executor.submit(query_virustotal_hash, ioc))
                futures.append(executor.submit(query_alienvault_hash, ioc))
                futures.append(executor.submit(query_hybrid_analysis_hash, ioc))
                futures.append(executor.submit(query_threatfox, ioc))
            elif ioc_type == "Email": # Check if the IOC is an email address
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
    main() # Run the main function