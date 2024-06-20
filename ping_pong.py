import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
import sys
import urllib.parse
import base64

def parse_har(har_file):
    '''
    Parses a HAR (HTTP Archive) file and returns a list of dictionaries representing entries.
    '''
    with open(har_file, 'r', encoding='utf-8') as f:
        har_data = json.load(f)
    
    result = []
    for entry in har_data['log']['entries']:
        item = {}

        # Extract request information
        startedDateTime = entry['startedDateTime']
        item['time'] = startedDateTime

        url = entry['request']['url']
        item['url'] = url

        parsed_url = urllib.parse.urlparse(url)
        item['host'] = parsed_url.hostname
        item['port'] = str(parsed_url.port) if parsed_url.port else ''
        item['protocol'] = parsed_url.scheme
        item['method'] = entry['request']['method']
        item['path'] = parsed_url.path

        # Extract request body if present
        if 'postData' in entry['request']:
            item['request'] = base64.b64encode(entry['request']['postData']['text'].encode('utf-8')).decode('utf-8')
        else:
            item['request'] = ''

        result.append(item)

    return result

def convert_to_xml(data):
    '''
    Converts parsed HAR data to XML format.
    '''
    items = ET.Element('items')
    items.set('burpVersion', '2023.10.3.5')  # Set your desired Burp Suite version here

    # Example: Set exportTime to current time
    import datetime
    export_time = datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")
    items.set('exportTime

