import re
from collections import Counter
import csv
from datetime import datetime

# Sample server log data (you can replace with actual log file)
sample_logs = [
    "2026-06-07 10:23:45 Failed password for user admin from 192.168.1.100",
    "2026-06-07 10:23:47 Failed password for user admin from 192.168.1.100",
    "2026-06-07 10:23:50 Failed password for user admin from 192.168.1.100",
    "2026-06-07 10:23:52 Failed password for user admin from 192.168.1.100",
    "2026-06-07 10:23:55 Failed password for user admin from 192.168.1.100",
    "2026-06-07 10:25:10 Successfully logged in user neha from 10.0.0.5",
    "2026-06-07 10:30:22 Failed password for user root from 203.0.113.45",
    "2026-06-07 10:30:25 Failed password for user root from 203.0.113.45",
    "2026-06-07 10:35:10 404 Not Found: /wp-admin/something",
    "2026-06-07 10:40:00 Failed password for user neha from 192.168.1.200",
    "2026-06-07 10:45:00 Successfully logged in user principal from 10.0.0.10",
]

def parse_logs(logs):
    """Parse logs and extract useful information"""
    
    failed_attempts = []
    ip_counter = Counter()
    error_404_count = 0
    successful_logins = []
    
    for log in logs:
        # Detect failed login attempts
        if "Failed" in log:
            failed_attempts.append(log)
            # Extract IP address using regex
            ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', log)
            if ip_match:
                ip_counter[ip_match.group()] += 1
        
        # Detect 404 errors
        if "404" in log:
            error_404_count += 1
        
        # Detect successful logins
        if "Successfully logged in" in log:
            successful_logins.append(log)
    
    # Flag IPs with more than 3 failed attempts (suspicious)
    suspicious_ips = {ip: count for ip, count in ip_counter.items() if count > 3}
    
    return {
        "total_failed_attempts": len(failed_attempts),
        "suspicious_ips": suspicious_ips,
        "error_404_count": error_404_count,
        "successful_logins": len(successful_logins),
        "total_logs_analyzed": len(logs)
    }

def generate_report(results):
    """Generate a readable report"""
    
    print("=" * 50)
    print("SERVER LOG ANALYSIS REPORT")
    print("=" * 50)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total logs analyzed: {results['total_logs_analyzed']}")
    print(f"Total failed login attempts: {results['total_failed_attempts']}")
    print(f"Total 404 errors: {results['error_404_count']}")
    print(f"Successful logins: {results['successful_logins']}")
    print("-" * 50)
    
    if results['suspicious_ips']:
        print("⚠️  SUSPICIOUS IP ADDRESSES DETECTED ⚠️")
        for ip, count in results['suspicious_ips'].items():
            print(f"   → {ip}: {count} failed attempts (BRUTE FORCE SUSPECTED)")
    else:
        print("✅ No suspicious IP addresses detected")
    
    print("=" * 50)
    
    # Save to CSV file
    with open('log_report.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Metric', 'Value'])
        writer.writerow(['Total Logs Analyzed', results['total_logs_analyzed']])
        writer.writerow(['Failed Login Attempts', results['total_failed_attempts']])
        writer.writerow(['404 Errors', results['error_404_count']])
        writer.writerow(['Successful Logins', results['successful_logins']])
        writer.writerow(['Suspicious IPs', str(results['suspicious_ips'])])
    
    print(f"\n📁 Full report saved to: log_report.csv")

# Run the analyzer
if __name__ == "__main__":
    print("🔍 Starting Server Log Analysis...\n")
    results = parse_logs(sample_logs)
    generate_report(results)