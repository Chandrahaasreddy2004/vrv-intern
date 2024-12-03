import csv
from collections import Counter, defaultdict

# Function to analyze the log file and extract required data
def analyze_log(file_path):
    # Counter for tracking the number of requests per IP
    ip_request_count = Counter()
    # Counter for tracking the number of accesses to each endpoint
    endpoint_count = Counter()
    # Dictionary to track failed login attempts by IP
    failed_login_count = defaultdict(int)

    # Threshold for flagging suspicious activity
    FAILED_LOGIN_THRESHOLD = 10

    # Open the log file for reading
    with open(file_path, 'r') as file:
        # Process each line in the log file
        for line in file:
            # Split the log entry into parts for easy extraction
            parts = line.split()
            # Skip lines that do not have sufficient parts
            if len(parts) < 9:
                continue
            
            # Extract the IP address from the log entry
            ip = parts[0]
            ip_request_count[ip] += 1
            
            # Extract the endpoint or resource being accessed
            endpoint = parts[6]
            endpoint_count[endpoint] += 1
            
            # Check the HTTP status code for failed login attempts
            status_code = parts[8]
            if status_code == '401':  # Status code 401 indicates unauthorized access
                failed_login_count[ip] += 1

    # Determine the most accessed endpoint (if any entries exist)
    top_endpoint = endpoint_count.most_common(1)[0] if endpoint_count else ("None", 0)

    # Identify suspicious IPs with failed login attempts exceeding the threshold
    suspicious_ips = {ip: count for ip, count in failed_login_count.items() if count > FAILED_LOGIN_THRESHOLD}

    return ip_request_count.most_common(), top_endpoint, suspicious_ips

# Function to display the results in the console
def log_results_to_console(ip_requests, top_endpoint, suspicious_ips):
    # Display the number of requests made by each IP address
    print("\nRequests per IP")
    print("IP Address,Request Count")
    for ip, count in ip_requests:
        print(f"{ip},{count}")
    
    # Display the most accessed endpoint along with its access count
    print("\nMost Accessed Endpoint")
    print("Endpoint,Access Count")
    print(f"{top_endpoint[0]},{top_endpoint[1]}")
    
    # Display suspicious activity, if any
    print("\nSuspicious Activity")
    print("IP Address,Failed Login Count")
    if suspicious_ips:  # Check if there are any flagged IPs
        for ip, count in suspicious_ips.items():
            print(f"{ip},{count}")
    else:  # If no suspicious IPs, output "None"
        print("None,0")

# Function to save the analysis results to a CSV file
def save_results_to_csv(ip_requests, top_endpoint, suspicious_ips, output_file_path):
    # Open the CSV file for writing
    with open(output_file_path, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)

        # Write the "Requests per IP" section to the CSV
        csvwriter.writerow(["Requests per IP"])
        csvwriter.writerow(["IP Address", "Request Count"])
        csvwriter.writerows(ip_requests)

        # Write the "Most Accessed Endpoint" section to the CSV
        csvwriter.writerow([])  # Add an empty row for separation
        csvwriter.writerow(["Most Accessed Endpoint"])
        csvwriter.writerow(["Endpoint", "Access Count"])
        csvwriter.writerow([top_endpoint[0], top_endpoint[1]])

        # Write the "Suspicious Activity" section to the CSV
        csvwriter.writerow([])  # Add an empty row for separation
        csvwriter.writerow(["Suspicious Activity"])
        csvwriter.writerow(["IP Address", "Failed Login Count"])
        if suspicious_ips:  # Write suspicious IPs if they exist
            csvwriter.writerows(suspicious_ips.items())
        else:  # Write "None" if no suspicious activity
            csvwriter.writerow(["None", "0"])


# Define file paths
log_file_path = 'sample.log'  # Path to the log file
output_file_path = 'log_analysis_results.csv'  # Path to save the CSV output

# Call the analysis function to process the log file
ip_requests, top_endpoint, suspicious_ips = analyze_log(log_file_path)

# Log the results to the console
log_results_to_console(ip_requests, top_endpoint, suspicious_ips)

# Save the results to a CSV file
save_results_to_csv(ip_requests, top_endpoint, suspicious_ips, output_file_path)
