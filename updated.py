import json
import base64
import xml.etree.ElementTree as ET
import urllib.parse as urlparse
from datetime import datetime

def parse_har_to_xml(har_file, xml_file, burp_version):
    # Load HAR data from a JSON file
    with open(har_file, 'r') as f:
        har_data = json.load(f)

    # Get current timestamp in ISO 8601 format
    export_time = datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'

    # Create XML structure
    root = ET.Element('items')
    root.set('burpVersion', burp_version)
    root.set('exportTime', export_time)

    entries = har_data['log']['entries']

    for entry in entries:
        item = ET.SubElement(root, 'item')

        time = ET.SubElement(item, 'time')
        time.text = entry['startedDateTime']

        url = ET.SubElement(item, 'url')
        url.text = entry['request']['url']

        host = ET.SubElement(item, 'host')
        host.set('ip', urlparse.urlparse(entry['request']['url']).hostname)  # Assuming URL parsing for host IP
        host.text = urlparse.urlparse(entry['request']['url']).hostname

        port = ET.SubElement(item, 'port')
        port.text = str(urlparse.urlparse(entry['request']['url']).port)

        protocol = ET.SubElement(item, 'protocol')
        protocol.text = urlparse.urlparse(entry['request']['url']).scheme

        method = ET.SubElement(item, 'method')
        method.text = entry['request']['method']

        path = ET.SubElement(item, 'path')
        path.text = urlparse.urlparse(entry['request']['url']).path

        extension = ET.SubElement(item, 'extension')
        extension.text = ''  # Adjust as per your requirements

        request = ET.SubElement(item, 'request')
        request.set('base64', 'true')
        request.text = base64.b64encode(json.dumps(entry['request'])).decode('utf-8')

        status = ET.SubElement(item, 'status')
        status.text = str(entry['response']['status'])

        responselength = ET.SubElement(item, 'responselength')
        responselength.text = str(entry['response']['bodySize'])

        mimetype = ET.SubElement(item, 'mimetype')
        mimetype.text = entry['response']['content']['mimeType']

        response = ET.SubElement(item, 'response')
        response.set('base64', 'true')
        response.text = base64.b64encode(entry['response']['content']['text'].encode('utf-8')).decode('utf-8')

        comment = ET.SubElement(item, 'comment')
        comment.text = ''  # Adjust as per your requirements

    # Create and write XML file
    tree = ET.ElementTree(root)
    tree.write(xml_file, encoding='utf-8', xml_declaration=True)

    print(f"Conversion successful. XML file '{xml_file}' has been created with Burp Suite version {burp_version} and export time {export_time}.")

# Example usage:
parse_har_to_xml('sample.har', 'converted_data.xml', '2023.3.5')
