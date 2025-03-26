import validators # Add this import for IOC validation
import re  # Add this import for stripping HTML tags

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