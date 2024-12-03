# vrv-intern

Count Requests per IP Address: The script reads the log file, extracts the IP addresses, and counts the number of requests made by each IP. It then sorts and displays these counts in descending order.

Identify the Most Frequently Accessed Endpoint: The script identifies and counts the number of accesses to each endpoint (URLs or resource paths) in the log. It then identifies the most frequently accessed endpoint and displays the endpoint along with its access count.

Detect Suspicious Activity: The script detects potential brute force login attempts by searching for failed login attempts (status code 401) in the log. It flags IP addresses with failed login attempts exceeding a specified threshold (default: 10 attempts) and displays these IP addresses along with their failed login counts.
