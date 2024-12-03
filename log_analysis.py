import re
import csv
from collections import Counter

# Parse log file
def parse_log(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

# Count requests per IP address
def count_requests_per_ip(logs):
    ip_pattern = r'^(\d+\.\d+\.\d+\.\d+)\s'
    ip_counts = Counter()
    for log in logs:
        match = re.match(ip_pattern, log)
        if match:
            ip_counts[match.group(1)] += 1
    return ip_counts

# Identify the most accessed endpoint
def most_accessed_endpoint(logs):
    endpoint_pattern = r'"\w+\s(.*?)\sHTTP'
    endpoint_counts = Counter()
    for log in logs:
        match = re.search(endpoint_pattern, log)
        if match:
            endpoint_counts[match.group(1)] += 1
    if endpoint_counts:
        return endpoint_counts.most_common(1)[0]
    else:
        return ('', 0)

# Detect suspicious activity (failed login attempts)
def detect_suspicious_activity(logs, threshold=10):
    failed_ip_counts = Counter()
    for log in logs:
        if '401' in log and 'Invalid credentials' in log:
            ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s', log)
            if ip_match:
                ip = ip_match.group(1)
                failed_ip_counts[ip] += 1
    return {ip: count for ip, count in failed_ip_counts.items() if count >= threshold}

# Write results to CSV
def write_to_csv(ip_counts, most_accessed, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])
        writer.writerow(["Suspicious IP", "Failed Login Attempts"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Display results in terminal
def display_results(ip_counts, most_accessed, suspicious_ips):
    print("IP Address           Request Count")
    for ip, count in sorted(ip_counts.items(), key=lambda item: item[1], reverse=True):
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

# Main function
def main():
    log_file = "sample.log"
    output_file = "log_analysis_results.csv"

    logs = parse_log(log_file)

    # Count IP requests
    ip_counts = count_requests_per_ip(logs)

    # Identify most accessed endpoint
    most_accessed = most_accessed_endpoint(logs)

    # Detect suspicious activity
    suspicious_ips = detect_suspicious_activity(logs)

    # Write to CSV
    write_to_csv(ip_counts, most_accessed, suspicious_ips, output_file)

    # Display results in terminal
    display_results(ip_counts, most_accessed, suspicious_ips)

    print("\nLog analysis complete. Results saved to:", output_file)

if __name__ == "__main__":
    main()