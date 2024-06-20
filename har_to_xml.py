import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
import sys
import urllib.parse

def parse_har(har_file):
    with open(har_file, 'r', encoding='utf-8') as f:
        har_data = json.load(f)
    return har_data

def har_to_xml_exact(har_data):
    items = ET.Element('items')
    items.set('burpVersion', '2023.10.3.5')  # Set your desired burp version here

    # Hardcoded export time example
    items.set('exportTime', 'Fri Jun 14 10:49:22 EDT 2024')

    for entry in har_data['log']['entries']:
        item = ET.SubElement(items, 'item')

        startedDateTime = entry['startedDateTime']
        time_elem = ET.SubElement(item, 'time')
        time_elem.text = startedDateTime

        url = entry['request']['url']
        url_elem = ET.SubElement(item, 'url')
        url_elem.text = url

        parsed_url = urllib.parse.urlparse(url)
        host_elem = ET.SubElement(item, 'host')
        host_elem.text = parsed_url.hostname
        if parsed_url.hostname:
            host_elem.set('ip', parsed_url.hostname)

        port_elem = ET.SubElement(item, 'port')
        port_elem.text = str(parsed_url.port) if parsed_url.port else ''

        protocol_elem = ET.SubElement(item, 'protocol')
        protocol_elem.text = parsed_url.scheme

        method_elem = ET.SubElement(item, 'method')
        method_elem.text = entry['request']['method']

        path_elem = ET.SubElement(item, 'path')
        path_elem.text = parsed_url.path

        extension_elem = ET.SubElement(item, 'extension')

        request_elem = ET.SubElement(item, 'request')
        request_elem.text = format_request(entry['request'])

        status_elem = ET.SubElement(item, 'status')

        responselength_elem = ET.SubElement(item, 'responselength')

        mimetype_elem = ET.SubElement(item, 'mimetype')

        response_elem = ET.SubElement(item, 'response')

        comment_elem = ET.SubElement(item, 'comment')

    return items

def format_request(request):
    request_str = f"{request['method']} {urllib.parse.urlparse(request['url']).path} {request['httpVersion']}\n"
    for header in request['headers']:
        request_str += f"{header['name']}: {header['value']}\n"
    request_str += "\n"
    return request_str

def prettify(elem):
    """Return a pretty-printed XML string for the Element."""
    rough_string = ET.tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python har_to_xml_exact_format.py <path_to_har_file>")
        sys.exit(1)
    
    har_file = sys.argv[1]
    har_data = parse_har(har_file)
    xml_data = har_to_xml_exact(har_data)
    print(prettify(xml_data))
