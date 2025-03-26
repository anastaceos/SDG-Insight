from tabulate import tabulate # Add this import for formatting results as a table
import html # Add this import for decoding HTML entities
import re # Add this import for stripping HTML tags
import textwrap # Add this import for wrapping text to 80 characters

def format_results_as_table(results):
    def format_value(value, indent=0):
        if isinstance(value, dict):
            # Special handling for URLscan.io results
            if "ip stats" in value or "domain" in value:
                formatted_urlscan = []
                for key, val in value.items():
                    if key == "ip stats":
                        formatted_urlscan.append(f"{' ' * indent}IP Stats:")
                        for ip_stat in val.get("requests", []):
                            if isinstance(ip_stat, dict):  # Ensure ip_stat is a dictionary
                                formatted_urlscan.append(
                                    f"{' ' * (indent + 2)}IP: {ip_stat.get('ip', 'Unknown')}\n"
                                    f"{' ' * (indent + 4)}Domains: {', '.join(ip_stat.get('domains', []))}\n"
                                    f"{' ' * (indent + 4)}Country: {ip_stat.get('country_name', 'Unknown')}\n"
                                    f"{' ' * (indent + 4)}ASN: {ip_stat.get('asn', 'Unknown')}\n"
                                )
                                # Handle nested fields like `geopip` or `dns` if present
                                if "geopip" in ip_stat:
                                    formatted_urlscan.append(f"{' ' * (indent + 4)}GeoIP:")
                                    for geo_key, geo_val in ip_stat["geopip"].items():
                                        formatted_urlscan.append(
                                            f"{' ' * (indent + 6)}{geo_key.capitalize()}: {geo_val}"
                                        )
                                if "dns" in ip_stat:
                                    formatted_urlscan.append(f"{' ' * (indent + 4)}DNS:")
                                    for dns_key, dns_val in ip_stat["dns"].items():
                                        formatted_urlscan.append(
                                            f"{' ' * (indent + 6)}{dns_key.capitalize()}: {dns_val}"
                                        )
                    elif key == "domain" and isinstance(val, dict):  # Ensure val is a dictionary
                        formatted_urlscan.append(f"{' ' * indent}Domain Info:")
                        formatted_urlscan.append(
                            f"{' ' * (indent + 2)}Domain: {val.get('domain', 'Unknown')}\n"
                            f"{' ' * (indent + 4)}IPs: {', '.join(val.get('ips', []))}\n"
                            f"{' ' * (indent + 4)}Countries: {', '.join(val.get('countries', []))}\n"
                        )
                    else:
                        formatted_urlscan.append(f"{' ' * indent}{key.capitalize()}: {format_value(val, indent + 2)}")
                return '\n'.join(formatted_urlscan)

            # General formatting for dictionaries
            formatted_dict = []
            for k, v in value.items():
                formatted_dict.append(f"{' ' * indent}{k}: {format_value(v, indent + 2)}")
            return '\n'.join(formatted_dict)

        elif isinstance(value, list):
            # Special handling for HIBP breaches
            formatted_list = []
            for item in value:
                if isinstance(item, dict) and "Name" in item and "BreachDate" in item:
                    # Format breach details
                    description = item.get('Description', 'No description')
                    description = html.unescape(description)  # Decode HTML entities
                    description = re.sub(r'<[^>]+>', '', description)  # Strip HTML tags
                    description = textwrap.fill(description, width=80)  # Wrap text to 80 characters
                    formatted_list.append(
                        f"{' ' * indent}Name: {item.get('Name', 'Unknown')}\n"
                        f"{' ' * (indent + 2)}Breach Date: {item.get('BreachDate', 'Unknown')}\n"
                        f"{' ' * (indent + 2)}Description:\n{textwrap.indent(description, ' ' * (indent + 4))}\n"
                        f"{' ' * (indent + 2)}Data Exposed: {', '.join(item.get('DataClasses', []))}\n"
                    )
                elif isinstance(item, dict):
                    # General formatting for nested dictionaries in lists
                    formatted_list.append(format_value(item, indent + 2))
                else:
                    # General formatting for other list items
                    formatted_list.append(f"{' ' * indent}- {str(item)}")
            return '\n'.join(formatted_list)

        elif value in [None, ""]:
            return "N/A"

        return str(value)

    # Create a table from the results dictionary
    table = []
    for key, value in results.items():
        # Skip entries where the value contains "error"
        if isinstance(value, str) and "error" in value.lower():
            continue
        # Split the key into tool and field
        if ": " in key:
            tool, field = key.split(": ", 1)
        else:
            tool, field = "SDG-Insight", key

        # Format the value
        formatted_value = format_value(value)
        table.append([tool, field, formatted_value])

    return tabulate(table, headers=["Source", "Attribute", "Details"], tablefmt="plain")