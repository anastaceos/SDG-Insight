from colorama import Fore, Style

# Function to display the tool banner
def display_banner(print_banner=True):
    """
    Displays the tool banner with optional color formatting.
    """
    banner = f"""
{Fore.CYAN}
            ____  ____   ____      ___ _   _ ____ ___ ____ _   _ _____ 
           / ___||  _ \\ / ___|    |_ _| \\ | / ___|_ _/ ___| | | |_   _|
           \\___ \\| | | | |  _ _____| ||  \\| \\___ \\| | |  _| |_| | | |  
            ___) | |_| | |_| |_____| || |\\  |___) | | |_| |  _  | | |  
           |____/|____/ \\____|    |___|_| \\_|____/___\\____|_| |_| |_|  
                                                             
{Style.RESET_ALL}
                  {Fore.YELLOW}SOC Analyst All-in-One Investigation Tool{Style.RESET_ALL}
          ------------------------------------------------------------
          - OSINT | Threat Intelligence | Incident Response
          - Integrated APIs: VirusTotal, URLScan, AbuseIPDB and more!
          - Developed for fast and efficient IOC analysis
          - Version: 1.0.0
          - Documentation: https://github.com/your-repo/SDG-Insight-OSINT
          ------------------------------------------------------------
    """
    if print_banner:
        print(banner)
    return banner