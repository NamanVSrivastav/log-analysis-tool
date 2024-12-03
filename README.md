# Web Server Log Analysis Script
This Python script is designed for monitoring web server logs and providing insightful analysis. It helps to track HTTP request patterns, identify potential security issues, and detect unusual activity. The script analyzes web server access logs, identifies the most frequent IP addresses, checks for failed login attempts, and reports other useful statistics. It’s particularly useful for system administrators or security teams looking to keep track of their web server's traffic and security issues.

## Features
- Analyzes web server logs (in common log format).
- Identifies top IP addresses based on request frequency.
- Tracks failed login attempts to detect potential security threats.
- Calculates the most frequently requested resources and their response codes.
- Option to set a threshold for failed login attempts for alerting.

## Requirements
- Python 3.x
- Required Python libraries:
- argparse
- collections
- re
You can install the required libraries using:
- pip install -r requirements.txt

## Usage
Run the script by providing the path to the log file:
- python log_analysis.py <logfile> --threshold <threshold_value>
- <logfile>: Path to the server log file.
- --threshold: Optional parameter to set a threshold for failed login attempts (default is 5).

Example:
- python log_analysis.py logs.txt --threshold 3
This will analyze the logs.txt file and alert if there are more than 3 failed login attempts from any IP.

## Sample Output

Top 5 IP Addresses:
1. 192.168.1.1: 10 requests
2. 203.0.113.5: 6 requests
3. 10.0.0.2: 5 requests

Failed Login Attempts:
1. 203.0.113.5: 3 attempts
2. 192.168.1.100: 2 attempts

Most Requested Resources:
1. /home: 15 requests
2. /login: 10 requests
3. /about: 8 requests
