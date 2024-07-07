
import json
import csv
import re
import urllib.parse

har_file = 'tester_of.har'  # Replace with your HAR file path

def parse_har(har_file):
    '''
    Parses a HAR file and returns a list of HTTP request/response pairs.
    '''
    result = []
    with open(har_file, 'r', encoding='utf-8') as file:
        har_data = json.load(file)
        for entry in har_data['log']['entries']:
            request = entry['request']
            response = entry['response']
            request_url = urllib.parse.unquote(request['url'])  # Decode URL once
            request_method = request['method']
            request_headers = {header['name']: header['value'] for header in request['headers']}
            request_body_params = request.get('postData', {}).get('params', [])
            response_status = response['status']
            response_time = entry['time']
            response_body = response.get('content', {}).get('text', '')
            response_headers = {header['name']: header['value'] for header in response.get('headers', [])}
            result.append((request_method, request_url, request_headers, request_body_params, response_status, response_time, response_body, response_headers))
    return result

def analyze_request_har(request_method, request_url, request_headers, request_body_params, response_status, response_time):
    '''
    Analyzes the HTTP request from HAR file and extracts features related to common attacks.
    '''
    # Initialize features with default values
    features = {
        'method': request_method,
        'path': request_url,
        'headers': str(request_headers),
        'body': '',  # Initialize empty, since we will concatenate if there's any content
        'body_length': 0,
        'num_commas': 0,
        'num_hyphens': 0,
        'num_brackets': 0,
        'num_quotes': 0,
        'num_double_quotes': 0,
        'num_slashes': 0,
        'num_braces': 0,
        'num_spaces': 0,
        'has_sql_keywords': 0,
        'has_xss_payload': 0,
        'has_csrf_token': 0,
        'response_status': response_status,
        'response_time': response_time
    }

    # Extract UID value from request_body_params
    uid_value = None
    if isinstance(request_body_params, list):
        for param in request_body_params:
            if isinstance(param, dict) and param.get('name') == 'uid':
                uid_value = param.get('value')
                break

    # Add debugging output to trace where the issue occurs
    print(f"Analyzing request: {request_method} {request_url}")
    print(f"Request headers: {request_headers}")
    print(f"Request body params: {request_body_params}")
    print(f"Extracted UID value: {uid_value}")

    if uid_value is None:
        print(f"UID value is None, skipping SQL keyword analysis for request: {request_method} {request_url}")
    else:
        print(f"UID value is '{uid_value}'")

    # Count characters in UID value
    if uid_value:
        features['body'] = uid_value
        features['body_length'] = len(uid_value)
        features['num_commas'] = uid_value.count(',')
        features['num_hyphens'] = uid_value.count('-')
        features['num_brackets'] = uid_value.count('(') + uid_value.count(')')
        features['num_quotes'] = uid_value.count("'")
        features['num_double_quotes'] = uid_value.count('"')
        features['num_slashes'] = uid_value.count('/')
        features['num_braces'] = uid_value.count('{') + uid_value.count('}')
        features['num_spaces'] = uid_value.count(' ')

        # Check for SQL keywords in the UID value (case-insensitive)
        sql_keywords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'TRUNCATE',
            'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'LIKE', 'BETWEEN', 'IN', 'JOIN', 'ON', 'GROUP BY', 'ORDER BY', 'HAVING', 'LIMIT'
        ]
        uid_value_lower = uid_value.lower()
        features['has_sql_keywords'] = int(any(keyword.lower() in uid_value_lower for keyword in sql_keywords))

    # Check for XSS payload in URL and headers (not in the body, as per your request)
    xss_patterns = [
        r'<script',                # <script
        r'alert\(',                # alert(
        r'\(alert\(',              # (alert(
        r'</script>',              # </script>
        r'document\.cookie',       # document.cookie
        r'eval\(',                 # eval(
        r'window\.location',       # window.location
        r'setTimeout\(',           # setTimeout(
        r'setInterval\(',          # setInterval(
        r'execCommand',            # execCommand
        r'innerHTML',              # innerHTML
        r'outerHTML',              # outerHTML
        r'document\.write',        # document.write
        r'XMLHttpRequest\.open',   # XMLHttpRequest.open
        r'FormData\.append',       # FormData.append
        r'document\.getElementById',  # document.getElementById
        r'document\.createElement',   # document.createElement
        r'document\.execCommand',     # document.execCommand
        r'window\.open',              # window.open
        r'window\.eval',              # window.eval
        r'window\.setTimeout',        # window.setTimeout
        r'window\.setInterval',       # window.setInterval
        r'document\.URL',             # document.URL
        r'location\.href',            # location.href
        r'location\.search',          # location.search
        r'document\.referrer',        # document.referrer
        r'navigator\.sendBeacon',     # navigator.sendBeacon
        r'importScripts',             # importScripts
        r'`',                         # `
        r'xss',                       # xss
    ]
    features['has_xss_payload'] = detect_xss_payload(request_url.lower(), str(request_headers), xss_patterns)

    # Check for CSRF token presence in headers
    csrf_keywords = ['csrf_token', 'anti_csrf_token', 'xsrf_token']  # Add other CSRF token keywords as needed
    csrf_pattern = r'\b({})\b'.format('|'.join(csrf_keywords))
    features['has_csrf_token'] = int(any(re.search(csrf_pattern, str(request_headers).lower()) for key in csrf_keywords))

    return features

def detect_xss_payload(request_url, request_headers, xss_patterns):
    '''
    Detects XSS payloads in the request URL and headers using specified patterns.
    '''
    # Decode URL-encoded payloads in the request URL
    decoded_url = request_url
    while True:
        temp_decoded_url = urllib.parse.unquote(decoded_url)
        if temp_decoded_url == decoded_url:
            break
        decoded_url = temp_decoded_url

    # Check XSS patterns in URL and headers
    for pattern in xss_patterns:
        if re.search(pattern, decoded_url, re.IGNORECASE) or re.search(pattern, request_headers, re.IGNORECASE):
            return 1
    return 0

# Parse HAR file and extract requests/responses
result_har = parse_har(har_file)

# Open the CSV file for writing
csv_file = 'http_log_with_security_analysis.csv'
with open(csv_file, "w", newline='', encoding='utf-8') as f:
    fieldnames = ['method', 'path', 'headers', 'body', 'body_length', 'num_commas', 'num_hyphens', 'num_brackets',
                  'num_quotes', 'num_double_quotes', 'num_slashes', 'num_braces', 'num_spaces', 'has_sql_keywords',
                  'has_xss_payload', 'has_csrf_token', 'response_status', 'response_time']
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()

    for request_method, request_url, request_headers, request_body_params, response_status, response_time, response_body, response_headers in result_har:
        features = analyze_request_har(request_method, request_url, request_headers, request_body_params, response_status, response_time)
        writer.writerow(features)

print(f"CSV file '{csv_file}' has been successfully created with analyzed HTTP request data from HAR file including security analysis for XSS, SQLi, and CSRF.")
