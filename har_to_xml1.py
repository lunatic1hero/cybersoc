import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
import sys
import urllib.parse

def parse_har(har_file):
    '''
    Parses a HAR (HTTP Archive) file and returns a dictionary of request and response pairs.
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

        item['extension'] = ''  # Placeholder for extension, not used in this example
        item['request'] = base64.b64encode(entry['request']['postData']['text'].encode('utf-8')).decode('utf-8') if 'postData' in entry['request'] else ''
        item['status'] = ''  # Placeholder for status, not used in this example
        item['responselength'] = ''  # Placeholder for response length, not used in this example
        item['mimetype'] = ''  # Placeholder for mimetype, not used in this example
        item['response'] = ''  # Placeholder for response, not used in this example
        item['comment'] = ''  # Placeholder for comment, not used in this example

        result.append(item)

    return result

def convert_to_xml(data):
    '''
    Converts parsed HAR data to XML format as per the specified structure.
    '''
    items = ET.Element('items')
    items.set('burpVersion', '2023.10.3.5')  # Set your desired Burp Suite version here

    # Example: Set exportTime to current time
    import datetime
    export_time = datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")
    items.set('exportTime', export_time)

    for entry in data:
        item = ET.SubElement(items, 'item')

        time_elem = ET.SubElement(item, 'time')
        time_elem.text = entry['time']

        url_elem = ET.SubElement(item, 'url')
        url_elem.text = entry['url']

        host_elem = ET.SubElement(item, 'host')
        host_elem.text = entry['host']
        if entry['host']:
            host_elem.set('ip', entry['host'])

        port_elem = ET.SubElement(item, 'port')
        port_elem.text = entry['port']

        protocol_elem = ET.SubElement(item, 'protocol')
        protocol_elem.text = entry['protocol']

        method_elem = ET.SubElement(item, 'method')
        method_elem.text = entry['method']

        path_elem = ET.SubElement(item, 'path')
        path_elem.text = entry['path']

        extension_elem = ET.SubElement(item, 'extension')
        extension_elem.text = entry['extension']

        request_elem = ET.SubElement(item, 'request')
        request_elem.text = entry['request']

        status_elem = ET.SubElement(item, 'status')
        status_elem.text = entry['status']

        responselength_elem = ET.SubElement(item, 'responselength')
        responselength_elem.text = entry['responselength']

        mimetype_elem = ET.SubElement(item, 'mimetype')
        mimetype_elem.text = entry['mimetype']

        response_elem = ET.SubElement(item, 'response')
        response_elem.text = entry['response']

        comment_elem = ET.SubElement(item, 'comment')
        comment_elem.text = entry['comment']

    return items

def prettify(elem):
    '''
    Return a pretty-printed XML string for the Element.
    '''
    rough_string = ET.tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python har_to_xml_converter.py <path_to_har_file>")
        sys.exit(1)
    
    har_file = sys.argv[1]
    har_data = parse_har(har_file)
    xml_data = convert_to_xml(har_data)
    xml_str = prettify(xml_data)

    # Print the XML content (for verification or further processing)
    print(xml_str)

    # Optionally, save the XML content to a file
    xml_output_file = 'output.xml'
    with open(xml_output_file, 'w', encoding='utf-8') as f:
        f.write(xml_str)

    print(f"XML file '{xml_output_file}' has been successfully created.")
