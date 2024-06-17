#from rawweb import RawWeb
from xml.etree import ElementTree as ET
import urllib.parse as urlparse
import base64
import csv
import re

log_path = 'demo_burp.log'

def parse_log(log_path):
    '''
    Parses the Burp Suite log XML file and returns a dictionary of request and response pairs.
    '''
    result = {}
    try:
        tree = ET.parse(log_path)
    except Exception as e:
        print("[+] Error!!! Failed to parse XML:", e)
        exit()

    root = tree.getroot()
    for reqs in root.findall('item'):
        raw_req = reqs.find('request').text
        raw_req = urlparse.unquote(raw_req)
        raw_resp = reqs.find('response').text
        result[raw_req] = raw_resp
    return result

def extract_headers(rawreq):
    '''
    Extracts headers, method, body, and path from a raw HTTP request.
    '''
    headers = {}
    body = ""
    try:
        raw = rawreq.decode('utf-8')
    except Exception as e:
        raw = rawreq

    parts = raw.split('\n\n', 1)
    if len(parts) > 1:
        head = parts[0]
        body = parts[1]
    else:
        head = parts[0]

    lines = head.splitlines()
    request_line = lines[0].split(' ', 2)
    method = request_line[0]
    path = request_line[1]

    for line in lines[1:]:
        if ': ' in line:
            key, value = line.split(': ', 1)
            headers[key] = value

    return headers, method, body, path

def analyze_request(rawreq):
    '''
    Analyzes the raw request and extracts features related to common attacks.
    '''
    headers, method, body, path = extract_headers(rawreq)

    # Features related to potential attacks
    features = {
        'method': method,
        'path': path,
        'headers': str(headers),
        'body': body,  # Include the body in the features
        'body_length': len(body),
        'num_commas': body.count(','),
        'num_hyphens': body.count('-'),
        'num_brackets': body.count('(') + body.count(')'),
        'has_sql_keywords': int(any(re.search(r'\b({})\b'.format('|'.join(['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'TRUNCATE'])), body, re.IGNORECASE))),
        'has_xss_payload': int(any(re.search(r'<script[\s>]', body, re.IGNORECASE))),
        'has_csrf_token': int('csrf_token' in body.lower()),
        'has_double_quotes': int('"' in body),
        # Add more features as needed based on your specific WAF requirements
    }

    return features

# Parse Burp Suite log and extract requests/responses
result = parse_log(log_path)

# Open the CSV file for writing
csv_file = 'http_log1.csv'
with open(csv_file, "w", newline='', encoding='utf-8') as f:
    fieldnames = ['method', 'path', 'headers', 'body', 'body_length', 'num_commas', 'num_hyphens', 'num_brackets', 'has_sql_keywords', 'has_xss_payload', 'has_csrf_token', 'has_double_quotes']
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()

    for item in result:
        raw_req = base64.b64decode(item).decode('utf-8')
        features = analyze_request(raw_req)
        writer.writerow(features)

print(f"CSV file '{csv_file}' has been successfully created with analyzed HTTP request data including body for POST requests and double quotes feature.")
