# cybersoc
building a web application firewall to prevent attacks like sql-injection and xss. 



Deployment
To deploy this Web Application Firewall (WAF), follow these steps:

1.Create the Directory Structure
*Create a main directory named WAF.
*Inside the WAF directory, create four sub-directories: data, models, notebook, and scripts.


The structure should look like this:
WAF/
├── data/
├── models/
├── notebooks/
└── scripts/

2.Download the Required Files
*In the data directory, download all_req_1.csv and clustered_results_with_features.csv.
*In the models directory, download kmeans_model.pkl.
*In the notebook directory, download analysis_notebook.ipynb.
*In the scripts directory, download proxy_interceptor.py.


3.Run the Proxy Interceptor Script
*Open a terminal and navigate to the WAF directory.
*Run the following command to start mitmdump with the proxy interceptor script:

----------->mitmdump -s scripts/proxy_interceptor.py




4.Configure Browser Proxy Settings
*Open your browser's settings.
*Navigate to the proxy settings section.
*Change the proxy settings to manual configuration.
*Set the HTTP proxy to localhost and the port to the one specified in the proxy_interceptor.py script (default is usually 8080).




5.Enter and Submit Payloads
*Access the web application and enter any SQL or XSS payloads.
*Submit the payloads on the respective website.


6.Check for Intrusions
*Return to your terminal.
*You will be able to see if the entered request is malicious or normal.
*If the request is malicious, an "intrusion detected" message will be displayed.
*If the request is not malicious, there will be no message.


By following these steps, you can successfully deploy and utilize the WAF to detect and respond to potentially malicious requests.
