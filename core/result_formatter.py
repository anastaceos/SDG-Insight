from tabulate import tabulate # Add this import for formatting results as a table
import html # Add this import for decoding HTML entities
import re # Add this import for stripping HTML tags
import textwrap # Add this import for wrapping text

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
            tool, field = "SDG-Insight", key

        # Format the value without splitting lists
        formatted_value = format_value(value)
        table.append([tool, field, formatted_value])

    return tabulate(table, headers=["Source", "Attribute", "Details"], tablefmt="plain")