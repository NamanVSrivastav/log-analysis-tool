import re
import csv
import argparse
from collections import defaultdict

# Constants
FAILED_LOGIN_THRESHOLD = 10  # Default threshold for failed login attempts

def parse_logs(log_file):
    """Parse the log file to extract IP requests, endpoints, and failed logins."""
    ip_requests = defaultdict(int)
    endpoints = defaultdict(int)
    failed_logins = defaultdict(int)

    # Regex patterns
    ip_pattern = r"(\d+\.\d+\.\d+\.\d+)"
    endpoint_pattern = r"\"(?:GET|POST|PUT|DELETE|HEAD) ([^ ]+) HTTP"
    status_code_pattern = r"\" (\d{3})"

    try:
        with open(log_file, 'r') as file:
            for line in file:
                ip_match = re.search(ip_pattern, line)
                endpoint_match = re.search(endpoint_pattern, line)
                status_code_match = re.search(status_code_pattern, line)

                if ip_match:
                    ip = ip_match.group(1)
                    ip_requests[ip] += 1

                if endpoint_match:
                    endpoint = endpoint_match.group(1)
                    endpoints[endpoint] += 1

                if status_code_match and status_code_match.group(1) == "401":
                    if ip_match:
                        ip = ip_match.group(1)
                        failed_logins[ip] += 1

    except FileNotFoundError:
        print(f"Error: The log file '{log_file}' does not exist.")
        return None, None, None

    return ip_requests, endpoints, failed_logins

def analyze_logs(ip_requests, endpoints, failed_logins, threshold):
    """Analyze parsed log data for requests, endpoints, and suspicious activity."""
    # Sort IP requests in descending order
    sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)

    # Find the most frequently accessed endpoint
    most_accessed_endpoint = max(endpoints.items(), key=lambda x: x[1], default=("None", 0))

    # Find IPs exceeding the failed login threshold
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}

    return sorted_ip_requests, most_accessed_endpoint, suspicious_ips

def save_to_csv(filename, sorted_ip_requests, most_accessed_endpoint, suspicious_ips):
    """Save analysis results to a CSV file."""
    try:
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)

            # Write requests per IP
            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            writer.writerows(sorted_ip_requests)
            writer.writerow([])

            # Write most accessed endpoint
            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow(most_accessed_endpoint)
            writer.writerow([])

            # Write suspicious activity
            writer.writerow(["Suspicious Activity"])
            writer.writerow(["IP Address", "Failed Login Count"])
            writer.writerows(suspicious_ips.items())

    except Exception as e:
        print(f"Error writing to CSV file: {e}")

def display_results(sorted_ip_requests, most_accessed_endpoint, suspicious_ips):
    """Display the analysis results in the terminal."""
    print("\nRequests per IP:")
    print(f"{'IP Address':<20}{'Request Count':<15}")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20}{count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20}{'Failed Login Attempts':<20}")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20}{count:<20}")

if __name__ == "__main__":
    # Command-line arguments
    parser = argparse.ArgumentParser(description="Analyze web server log files for requests, endpoints, and suspicious activity.")
    parser.add_argument("logfile", help="Path to the log file.")
    parser.add_argument("--threshold", type=int, default=FAILED_LOGIN_THRESHOLD, help="Threshold for failed login attempts (default: 10).")
    args = parser.parse_args()

    # Parse the logs
    ip_requests, endpoints, failed_logins = parse_logs(args.logfile)
    if ip_requests is None:
        exit(1)

    # Analyze the logs
    sorted_ip_requests, most_accessed_endpoint, suspicious_ips = analyze_logs(ip_requests, endpoints, failed_logins, args.threshold)

    # Display results
    display_results(sorted_ip_requests, most_accessed_endpoint, suspicious_ips)

    # Save results to CSV
    save_to_csv("log_analysis_results.csv", sorted_ip_requests, most_accessed_endpoint, suspicious_ips)
    print("\nResults saved to 'log_analysis_results.csv'")
