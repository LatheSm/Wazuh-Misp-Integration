#!/usr/bin/env python

import sys
import os
import json
import requests
from requests.exceptions import ConnectionError, HTTPError
from socket import socket, AF_UNIX, SOCK_DGRAM
import time

# Enable or disable debugging
debug_enabled = True  # Set to False to disable debug logging

# File and socket paths
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = f'{pwd}/queue/sockets/queue'

# Set paths for logging
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
log_file = f'{pwd}/logs/integrations.log'

def debug(msg):
    """Log debug messages."""
    if debug_enabled:
        timestamped_msg = f"{now}: {msg}\n"
        print(timestamped_msg)
        with open(log_file, "a") as f:
            f.write(timestamped_msg)

def send_event(msg, agent=None):
    """Send an event to the Wazuh Manager."""
    try:
        if not agent or agent["id"] == "000":
            string = f'1:misp:{json.dumps(msg)}'
        else:
            string = f'1:[{agent["id"]}] ({agent["name"]}) {agent["ip"] if "ip" in agent else "any"}->misp:{json.dumps(msg)}'
        
        debug(f"Sending Event: {string}")
        with socket(AF_UNIX, SOCK_DGRAM) as sock:
            sock.connect(socket_addr)
            sock.send(string.encode())
    except Exception as e:
        debug(f"Error sending event: {e}")

# Read configuration parameters
try:
    with open(sys.argv[1]) as alert_file:
        alert = json.load(alert_file)
    debug("Alert loaded successfully")
except Exception as e:
    debug(f"Error reading alert file: {e}")
    sys.exit(1)

# MISP Server Base URL and API Key
misp_base_url = "https://{MISP IP}/attributes/restSearch/"
misp_api_auth_key = "{MISP API KEY}"

# API - HTTP Headers
misp_apicall_headers = {
    "Content-Type": "application/json",
    "Authorization": misp_api_auth_key,
    "Accept": "application/json"
}

# Extract Event Source and Type
try:
    event_source = alert["rule"]["groups"][1]
    debug(f"Event source: {event_source}")
except KeyError as e:
    debug(f"Missing expected key in alert: {e}")
    sys.exit(1)

if event_source == 'syscheck':
    try:
        client_ip = alert["syscheck"]["sha256_after"]
        debug(f"Extracted Client IP: {client_ip}")
        misp_search_value = f"value:{client_ip}"
        misp_search_url = f'{misp_base_url}{misp_search_value}'
        debug(f"MISP API URL: {misp_search_url}")
        file_path = alert["syscheck"]["path"]
        
        # Check if client_ip is in the known empty file hash list
        if client_ip in [
            "{add false positive hashes here}",

            "{false positive hash}"
        ]:
            sys.exit("Exiting due to Hash being a False Positive")
        
        # Make API request to MISP
        try:
            misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=False)
            misp_api_response.raise_for_status()
            debug("API request successful")
        except (ConnectionError, HTTPError) as api_err:
            debug(f"API Error: {api_err}")
            sys.exit(1)
        
        # Process response
        try:
            misp_api_response = misp_api_response.json()
            debug(f"API Response Data: {misp_api_response}")
            
            if "Attribute" in misp_api_response["response"] and misp_api_response["response"]["Attribute"]:
                attribute = misp_api_response["response"]["Attribute"][0]
                alert_output = {
                    "misp": {
                        "event_id": attribute["event_id"],
                        "category": attribute["category"],
                        "value": attribute["value"],
                        "type": attribute["type"],
                        "comment": attribute["comment"],
                        "file_path": file_path
                    },
                    "integration": "misp"
                }
                debug(f"Alert Output: {alert_output}")
                send_event(alert_output, alert.get("agent"))
            else:
                debug("No Attributes found in MISP response")
                sys.exit(1)
        except json.JSONDecodeError as json_err:
            debug(f"JSON Parsing Error: {json_err}")
            sys.exit(1)
    
    except KeyError as e:
        debug(f"Missing expected key: {e}")
        sys.exit(1)
else:
    debug(f"Event source is not 'syscheck': {event_source}")
    sys.exit()

