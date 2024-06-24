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
            
            # Extracting the UID parameter value from postData
            postData = request.get('postData', {})
            request_body = postData.get('text', '')
            postData_params = {param['name']: param['value'] for param in postData.get('params', [])}
            uid_value = postData_params.get('uid', '')
            
            response_body = response.get('content', {}).get('text', '')

            result.append((request_method, request_url, request_headers, uid_value, request_body, response_body))

    return result

def analyze_request_har(request_method, request_url, request_headers, uid_value, request_body):
    '''
    Analyzes the HTTP request from HAR file and extracts features related to common attacks.
    '''
    # Initialize features with default values
    features = {
        'method': request_method,
        'path': request_url,
        'headers': str(request_headers),
        'body': uid_value if uid_value else '',  # Set default value for uid_value
        'body_length': len(uid_value) if uid_value else 0,
        'num_commas': uid_value.count(',') if uid_value else 0,
        'num_hyphens': uid_value.count('-') if uid_value else 0,
        'num_brackets': uid_value.count('(') + uid_value.count(')') if uid_value else 0,
        'has_sql_keywords': 0,
        'has_xss_payload': 0,
        'has_csrf_token': 0,
        'has_double_quotes': int('"' in uid_value),
        # Add more features as needed based on your specific WAF requirements
    }

    # Check for SQL keywords in the uid_value
    if uid_value:
        sql_keywords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'TRUNCATE',
            'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'LIKE', 'BETWEEN', 'IN', 'JOIN', 'ON', 'GROUP BY', 'ORDER BY', 'HAVING', 'LIMIT'
        ]
        features['has_sql_keywords'] = int(any(re.search(r'\b({})\b'.format('|'.join(sql_keywords)), uid_value, re.IGNORECASE)))
        features['has_sql_keywords'] |= detect_sqli_payload(request_url, uid_value)

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
    features['has_xss_payload'] = detect_xss_payload(request_url.lower(), request_body.lower(), xss_patterns)

    # Check for CSRF token presence
    csrf_keywords = ['csrf_token', 'anti_csrf_token', 'xsrf_token']  # Add other CSRF token keywords as needed
    csrf_pattern = r'\b({})\b'.format('|'.join(csrf_keywords))
    features['has_csrf_token'] = int(any(re.search(csrf_pattern, request_body.lower()) or key.lower() in request_headers for key in csrf_keywords))

    return features

def detect_xss_payload(request_url, request_body, xss_patterns):
    '''
    Detects XSS payloads in the request URL and body using specified patterns.
    '''
    # Decode URL-encoded payloads in the request URL and body
    decoded_url = urllib.parse.unquote(request_url)
    decoded_body = urllib.parse.unquote(request_body)

    # Check XSS patterns in both URL and body
    for pattern in xss_patterns:
        if re.search(pattern, decoded_url, re.IGNORECASE) or re.search(pattern, decoded_body, re.IGNORECASE):
            return 1
    return 0

def detect_sqli_payload(request_url, request_body):
    '''
    Detects SQLi payloads in the request URL and body using specified patterns.
    '''
    # Decode URL-encoded payloads in the request URL and body
    decoded_url = urllib.parse.unquote(request_url)
    decoded_body = urllib.parse.unquote(request_body)

    # SQL injection patterns
    sqli_patterns = [
        r'\bSELECT\b.*?\bFROM\b',       # SELECT ... FROM ...
        r'\bINSERT INTO\b',             # INSERT INTO ...
        r'\bUPDATE\b.*?\bSET\b',        # UPDATE ... SET ...
        r'\bDELETE FROM\b',             # DELETE FROM ...
        r'\bDROP TABLE\b',              # DROP TABLE ...
        r'\bTRUNCATE TABLE\b',          # TRUNCATE TABLE ...
        r'\bCREATE TABLE\b',            # CREATE TABLE ...
        r'\bALTER TABLE\b',             # ALTER TABLE ...
        r'\bUNION\b.*?\bSELECT\b',      # UNION ... SELECT ...
        r'\bWHERE\b.*?\b=\b',           # WHERE ... =
        r'\bAND\b.*?\b=\b',             # AND ... =
        r'\bOR\b.*?\b=\b',              # OR ... =
        r'\bLIKE\b',                    # LIKE ...
        r'\bBETWEEN\b',                 # BETWEEN ...
        r'\bIN\b',                      # IN ...
        r'\bJOIN\b',                    # JOIN ...
        r'\bGROUP BY\b',                # GROUP BY ...
        r'\bORDER BY\b',                # ORDER BY ...
        r'\bHAVING\b',                  # HAVING ...
        r'\bLIMIT\b',                   # LIMIT ...
    ]

    # Check SQLi patterns in decoded URL and body
    for pattern in sqli_patterns:
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

    for request_method, request_url, request_headers, uid_value, request_body, response_body in result_har:
        features = analyze_request_har(request_method, request_url, request_headers, uid_value, request_body)
        writer.writerow(features)

print(f"CSV file '{csv_file}' has been successfully created with analyzed HTTP request data from HAR file including security analysis for XSS, SQLi, and CSRF.")
