from tabulate import tabulate # Add this import for formatting results as a table
import html # Add this import for decoding HTML entities
import re # Add this import for stripping HTML tags
import textwrap # Add this import for wrapping text to 80 characters

def format_results_as_table(results):
    def format_value(value, indent=0):
        if isinstance(value, dict):
            # Format dictionaries with indentation
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
                else:
                    # Format other list items
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