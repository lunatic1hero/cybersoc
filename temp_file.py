import json
import csv
import re

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
            request_url = request['url']
            request_method = request['method']
            request_headers = {header['name']: header['value'] for header in request['headers']}
            request_body = request.get('postData', {}).get('text', '')
            response_body = response.get('content', {}).get('text', '')

            result.append((request_method, request_url, request_headers, request_body, response_body))

    return result

def analyze_request_har(request_method, request_url, request_headers, request_body):
    '''
    Analyzes the HTTP request from HAR file and extracts features related to common attacks.
    '''
    # Initialize features with default values
    features = {
        'method': request_method,
        'path': request_url,
        'headers': str(request_headers),
        'body': request_body if request_body else '',  # Set default value for request_body
        'body_length': len(request_body) if request_body else 0,
        'num_commas': request_body.count(',') if request_body else 0,
        'num_hyphens': request_body.count('-') if request_body else 0,
        'num_brackets': request_body.count('(') + request_body.count(')') if request_body else 0,
        'has_sql_keywords': 0,
        'has_xss_payload': 0,
        'has_csrf_token': 0,
        'has_double_quotes': 0,
        # Add more features as needed based on your specific WAF requirements
    }

    # Check if request_body is not None or empty
    if request_body:
        # Features related to potential attacks
        features.update({
            'has_sql_keywords': int(any(re.search(r'\b({})\b'.format('|'.join(['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'TRUNCATE'])), request_body, re.IGNORECASE))),
            'has_xss_payload': int('<script' in request_body.lower()),
            'has_double_quotes': int('"' in request_body),
            # Check for CSRF token presence
            'has_csrf_token': int('csrf_token' in request_body.lower()) or 'csrf_token' in request_headers
        })

    return features

# Parse HAR file and extract requests/responses
result_har = parse_har(har_file)

# Open the CSV file for writing
csv_file = 'http_log_with_security_analysis.csv'
with open(csv_file, "w", newline='', encoding='utf-8') as f:
    fieldnames = ['method', 'path', 'headers', 'body', 'body_length', 'num_commas', 'num_hyphens', 'num_brackets', 'has_sql_keywords', 'has_xss_payload', 'has_csrf_token', 'has_double_quotes']
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()

    for request_method, request_url, request_headers, request_body, response_body in result_har:
        features = analyze_request_har(request_method, request_url, request_headers, request_body)
        writer.writerow(features)

print(f"CSV file '{csv_file}' has been successfully created with analyzed HTTP request data from HAR file including security analysis for XSS, SQLi, and CSRF.")
