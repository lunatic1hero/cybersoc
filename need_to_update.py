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
            request_url = urllib.parse.unquote(request['url'])  # Decode URL
            request_method = request['method']
            request_headers = {header['name']: header['value'] for header in request['headers']}
            
            # Check if postData is present and parse it
            if 'postData' in request:
                request_body = request['postData']
                if 'text' in request_body:
                    request_body_text = request_body['text']
                    # Parse parameters if available
                    try:
                        request_body_params = urllib.parse.parse_qs(request_body_text)
                    except ValueError:
                        request_body_params = {}
            else:
                request_body_text = ''
                request_body_params = {}

            response_body = response.get('content', {}).get('text', '')

            result.append((request_method, request_url, request_headers, request_body_params, response_body))

    return result

def analyze_request_har(request_method, request_url, request_headers, request_body_params):
    '''
    Analyzes the HTTP request from HAR file and extracts features related to common attacks.
    '''
    # Initialize features with default values
    features = {
        'method': request_method,
        'path': request_url,
        'headers': str(request_headers),
        'body': json.dumps(request_body_params) if request_body_params else '',  # Serialize body to JSON
        'body_length': len(request_body_params) if request_body_params else 0,
        'num_commas': json.dumps(request_body_params).count(',') if request_body_params else 0,
        'num_hyphens': json.dumps(request_body_params).count('-') if request_body_params else 0,
        'num_brackets': json.dumps(request_body_params).count('(') + json.dumps(request_body_params).count(')') if request_body_params else 0,
        'has_sql_keywords': 0,
        'has_xss_payload': 0,
        'has_csrf_token': 0,
        'has_double_quotes': 0,
        # Add more features as needed based on your specific WAF requirements
    }

    # Extract UID value if present
    uid_value = next((param['value'][0] for param in request_body_params.get('uid', []) if param.get('name') == 'uid'), None)

    # Check for SQL keywords in UID value
    if uid_value:
        sql_keywords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'TRUNCATE',
            'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'LIKE', 'BETWEEN', 'IN', 'JOIN', 'ON', 'GROUP BY', 'ORDER BY', 'HAVING', 'LIMIT'
        ]
        features['has_sql_keywords'] = int(any(re.search(r'\b({})\b'.format('|'.join(sql_keywords)), uid_value, re.IGNORECASE)))

    # Check for XSS payload in both URL and body
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
    ]
    features['has_xss_payload'] = detect_xss_payload(request_url.lower(), json.dumps(request_body_params).lower(), xss_patterns)

    # Check for CSRF token presence
    csrf_keywords = ['csrf_token', 'anti_csrf_token', 'xsrf_token']  # Add other CSRF token keywords as needed
    csrf_pattern = r'\b({})\b'.format('|'.join(csrf_keywords))
    features['has_csrf_token'] = int(any(re.search(csrf_pattern, json.dumps(request_body_params).lower()) or key.lower() in request_headers for key in csrf_keywords))

    # Check for double quotes
    features['has_double_quotes'] = int('"' in json.dumps(request_body_params))

    return features

def detect_xss_payload(request_url, request_body_params, xss_patterns):
    '''
    Detects XSS payloads in the request URL and body using specified patterns.
    '''
    # Decode URL-encoded payloads in the request URL and body
    decoded_url = urllib.parse.unquote(request_url)
    decoded_body = urllib.parse.unquote(request_body_params)

    # Check XSS patterns in both URL and body
    for pattern in xss_patterns:
        if re.search(pattern, decoded_url, re.IGNORECASE) or re.search(pattern, decoded_body, re.IGNORECASE):
            return 1
    return 0

# Parse HAR file and extract requests/responses
result_har = parse_har(har_file)

# Open the CSV file for writing
csv_file = 'http_log_with_security_analysis.csv'
with open(csv_file, "w", newline='', encoding='utf-8') as f:
    fieldnames = ['method', 'path', 'headers', 'body', 'body_length', 'num_commas', 'num_hyphens', 'num_brackets', 'has_sql_keywords', 'has_xss_payload', 'has_csrf_token', 'has_double_quotes']
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()

    for request_method, request_url, request_headers, request_body_params, response_body in result_har:
        features = analyze_request_har(request_method, request_url, request_headers, request_body_params)
        writer.writerow(features)

print(f"CSV file '{csv_file}' has been successfully created with analyzed HTTP request data from HAR file including security analysis for XSS, SQLi, and CSRF.")
