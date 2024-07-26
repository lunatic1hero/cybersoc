import json
import re
import urllib.parse
from mitmproxy import http
import pandas as pd
from pycaret.clustering import load_model, predict_model

# Defining SQL keywords and XSS patterns globally
sql_keywords = [
    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'TRUNCATE',
    'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'LIKE', 'BETWEEN', 'IN', 'JOIN', 'ON', 'GROUP BY', 'ORDER BY', 'HAVING', 'LIMIT'
]

xss_patterns = [
    r'<script', r'alert\(', r'\(alert\(', r'</script>', r'document\.cookie',
    r'eval\(', r'window\.location', r'setTimeout\(', r'setInterval\(',
    r'execCommand', r'innerHTML', r'outerHTML', r'document\.write',
    r'XMLHttpRequest\.open', r'FormData\.append', r'document\.getElementById',
    r'document\.createElement', r'document\.execCommand', r'window\.open',
    r'window\.eval', r'window\.setTimeout', r'window\.setInterval',
    r'document\.URL', r'location\.href', r'location\.search',
    r'document\.referrer', r'navigator\.sendBeacon', r'importScripts', r'`'
]

# Loading the K-Means model
model = load_model('models/kmeans_model')

def parse_request(flow: http.HTTPFlow):
    request = flow.request
    request_url = urllib.parse.unquote(request.pretty_url)  # Decode URL
    request_method = request.method
    request_headers = {k: v for k, v in request.headers.items()}
    request_body = request.get_text()
    
    # Extracting UID value if present
    uid_value = None
    if request_body:
        for param in request_body.split('&'):
            if param.startswith('uid='):
                uid_value = param.split('=')[1]
                break
    
    # Extracting features
    features = {
        'method': request_method,
        'path': request_url,
        'headers': str(request_headers),
        'body': uid_value if uid_value else '',
        'body_length': len(uid_value) if uid_value else 0,
        'num_commas': uid_value.count(',') if uid_value else 0,
        'num_hyphens': uid_value.count('-') if uid_value else 0,
        'num_brackets': uid_value.count('(') + uid_value.count(')') if uid_value else 0,
        'num_quotes': uid_value.count("'") if uid_value else 0,
        'num_double_quotes': uid_value.count('"') if uid_value else 0,
        'num_slashes': uid_value.count('/') if uid_value else 0,
        'num_braces': uid_value.count('{') + uid_value.count('}') if uid_value else 0,
        'num_spaces': uid_value.count(' ') if uid_value else 0,
        'has_sql_keywords': int(any(keyword.lower() in uid_value.lower() for keyword in sql_keywords)) if uid_value else 0,
        'has_xss_payload': int(any(re.search(pattern, request_url.lower()) or re.search(pattern, str(request_headers).lower()) for pattern in xss_patterns)),
        'has_csrf_token': int(any('csrf_token' in k.lower() or 'anti_csrf_token' in k.lower() or 'xsrf_token' in k.lower() for k in request_headers)),
        'response_status': 0,  # This will be updated later
        'response_time': 0  # This will be updated later
    }
    
    return features

def response(flow: http.HTTPFlow):
    # Updating the response details
    response = flow.response
    features = parse_request(flow)
    features['response_status'] = response.status_code
    features['response_time'] = flow.response.timestamp_end - flow.request.timestamp_start
    
    # Creating a DataFrame with the new request
    new_request_df = pd.DataFrame([features])
    new_request_df['nature'] = 'new request'
    
    # Loading the existing clustered data
    clustered_data = pd.read_csv('data/clustered_results_with_features.csv')
    
    # Predicting the cluster for the new request
    prediction = predict_model(model, data=new_request_df)
    new_request_df['Cluster'] = prediction['Cluster'].values[0]
    
    # Appending the new request to the existing clustered data
    updated_data = clustered_data.append(new_request_df, ignore_index=True)
    
    # Checking if the new cluster has the highest number of requests
    cluster_counts = updated_data['Cluster'].value_counts()
    new_cluster = new_request_df['Cluster'].values[0]
    if cluster_counts[new_cluster] < cluster_counts.max():
        print(f"Intrusion detected! New request added to cluster {new_cluster} but cluster {cluster_counts.idxmax()} has more requests.")
    
    # Save the updated data
    updated_data.to_csv('data/clustered_results_with_features.csv', index=False)

# To run this script with mitmproxy, use the following command:
# mitmdump -s scripts/proxy_interceptor.py
