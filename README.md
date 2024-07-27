--------->if you dont want to know about the process then you can directly read IMPLEMENT.md file



# WAF Project - Web Application Firewall

## Overview

This project involves the development of a Web Application Firewall (WAF) with the following components:

1. *Log Parser*: A Python script that parses logs and extracts features related to Cross-Site Scripting (XSS) and SQL Injection (SQLI) attacks. The extracted features are saved in a CSV file.
2. *Model Training*: The CSV file is used to train a clustering model using the K-means algorithm.
3. *Proxy Interceptor*: A Python script using mitmproxy to intercept web requests, classify them into clusters, and determine if they are safe or potentially harmful.

## Project Components

### 1. Log Parser

The log parser is designed to process logs and extract specific features indicative of XSS and SQLI attacks. The output is stored in a CSV file, which is later used for model training.

### 2. Model Training

Using the features extracted by the log parser, we train a clustering model with K-means. This model helps in categorizing requests into different clusters based on their characteristics.

### 3. Proxy Interceptor

The proxy interceptor uses mitmproxy to intercept web requests and analyze them using the trained clustering model. Depending on the cluster to which a request belongs, the system determines if the request is safe or potentially harmful.

## Implementation Details

For detailed instructions on implementing this project, please refer to the IMPLEMENT.md file in the repository.

## FAQ

### What are the contents in CSV files?

The CSV files contain features generated by the log parser from web request logs. These features are used to train the clustering model.

### What is the implement section?

The implement section provides detailed instructions for implementing the WAF project in your system. Refer to the IMPLEMENT.md file in the repository for more information.

### What are Log Parsers?

Log parsers are tools used to process and analyze logs. In this project, we have two types of log parsers:
- *XML Format Parser*: This parser is designed to work with logs in XML format.
- *HAR Format Parser*: The primary parser used in this project, compatible with HAR format logs, which are extensively used due to the availability of large datasets.

### What are Request Logs?

Request logs are records of requests made to a web application. In this project, we used the OWASP Zap tool to generate request logs:
- *Good Requests*: Generated using the Spider tool in OWASP Zap.
- *Malicious Requests*: Generated using fuzzdb to simulate SQLI and XSS attacks.

### Sources

The log parsers were designed with the help of files available in this section.



Let me know if there's anything you'd like to modify or add!
