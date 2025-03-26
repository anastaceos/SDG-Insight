import requests # Import the requests library to query APIs
import logging # Import the logging module for logging

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