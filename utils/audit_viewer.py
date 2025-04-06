#!/usr/bin/env python
"""
Audit Log Viewer

A utility to view, search, and analyze the security audit logs
for data access patterns and security events.
"""

import os
import sys
import json
import argparse
import datetime
from collections import Counter, defaultdict
from tabulate import tabulate

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.audit_logger import ensure_log_dir

def parse_log_line(line):
    """Parse a single line from the audit log"""
    # Skip empty lines
    if not line.strip():
        return None
    
    # Try to parse JSON lines
    if line.strip().startswith('{'):
        try:
            return json.loads(line.strip())
        except json.JSONDecodeError:
            pass
    
    # Parse standard log format
    parts = line.strip().split(' | ', 2)
    if len(parts) >= 3:
        timestamp, level, message = parts
        return {
            "timestamp": timestamp,
            "level": level,
            "message": message,
            "is_summary": True
        }
    
    # Couldn't parse this line
    return None

def load_audit_logs():
    """Load and parse the audit logs"""
    log_dir = ensure_log_dir()
    log_file = os.path.join(log_dir, 'access_audit.log')
    
    logs = []
    
    if not os.path.exists(log_file):
        print(f"No audit log file found at {log_file}")
        return logs
    
    with open(log_file, 'r') as f:
        for line in f:
            log_entry = parse_log_line(line)
            if log_entry:
                logs.append(log_entry)
    
    return logs

def filter_logs(logs, args):
    """Filter logs based on command-line arguments"""
    filtered = logs.copy()
    
    # Filter by user email
    if args.email:
        filtered = [
            log for log in filtered 
            if not log.get('is_summary', False) and 
            log.get('user_email') and 
            args.email.lower() in log.get('user_email', '').lower()
        ]
    
    # Filter by access status (granted/denied)
    if args.status:
        if args.status.lower() == 'granted':
            filtered = [
                log for log in filtered 
                if not log.get('is_summary', False) and log.get('access_granted') is True
            ]
        elif args.status.lower() == 'denied':
            filtered = [
                log for log in filtered 
                if not log.get('is_summary', False) and log.get('access_granted') is False
            ]
    
    # Filter by endpoint
    if args.endpoint:
        filtered = [
            log for log in filtered 
            if not log.get('is_summary', False) and 
            log.get('endpoint') and 
            args.endpoint.lower() in log.get('endpoint', '').lower()
        ]
    
    # Filter by date range
    if args.start_date:
        start_date = datetime.datetime.strptime(args.start_date, "%Y-%m-%d")
        filtered = [
            log for log in filtered 
            if not log.get('is_summary', False) and 
            log.get('timestamp') and 
            datetime.datetime.fromisoformat(log.get('timestamp').split('T')[0]) >= start_date
        ]
    
    if args.end_date:
        end_date = datetime.datetime.strptime(args.end_date, "%Y-%m-%d")
        end_date = end_date + datetime.timedelta(days=1)  # Include the end date
        filtered = [
            log for log in filtered 
            if not log.get('is_summary', False) and 
            log.get('timestamp') and 
            datetime.datetime.fromisoformat(log.get('timestamp').split('T')[0]) < end_date
        ]
    
    return filtered

def generate_summary(logs):
    """Generate a summary of the audit logs"""
    # Only process JSON entries
    json_logs = [log for log in logs if not log.get('is_summary', False)]
    
    if not json_logs:
        return {
            "total_attempts": 0,
            "granted": 0,
            "denied": 0,
            "unique_users": 0,
            "top_users": [],
            "top_endpoints": [],
            "top_ip_addresses": []
        }
    
    # Calculate basic stats
    total_attempts = len(json_logs)
    granted = sum(1 for log in json_logs if log.get('access_granted') is True)
    denied = sum(1 for log in json_logs if log.get('access_granted') is False)
    
    # Count unique users
    users = set()
    for log in json_logs:
        if log.get('user_email'):
            users.add(log.get('user_email'))
    
    # Count access by user
    user_counter = Counter()
    for log in json_logs:
        if log.get('user_email'):
            user_counter[log.get('user_email')] += 1
    
    # Count access by endpoint
    endpoint_counter = Counter()
    for log in json_logs:
        if log.get('endpoint'):
            endpoint_counter[log.get('endpoint')] += 1
    
    # Count access by IP address
    ip_counter = Counter()
    for log in json_logs:
        if log.get('ip_address'):
            ip_counter[log.get('ip_address')] += 1
    
    # Get top entries
    top_users = user_counter.most_common(5)
    top_endpoints = endpoint_counter.most_common(5)
    top_ip_addresses = ip_counter.most_common(5)
    
    return {
        "total_attempts": total_attempts,
        "granted": granted,
        "denied": denied,
        "unique_users": len(users),
        "top_users": top_users,
        "top_endpoints": top_endpoints,
        "top_ip_addresses": top_ip_addresses
    }

def print_summary(summary):
    """Print a summary of the audit logs"""
    print("\n===== AUDIT LOG SUMMARY =====\n")
    
    print(f"Total access attempts: {summary['total_attempts']}")
    print(f"Access granted: {summary['granted']}")
    print(f"Access denied: {summary['denied']}")
    print(f"Unique users: {summary['unique_users']}\n")
    
    if summary['top_users']:
        print("Top users:")
        print(tabulate(summary['top_users'], headers=["User", "Access Attempts"]))
        print()
    
    if summary['top_endpoints']:
        print("Top endpoints:")
        print(tabulate(summary['top_endpoints'], headers=["Endpoint", "Access Attempts"]))
        print()
    
    if summary['top_ip_addresses']:
        print("Top IP addresses:")
        print(tabulate(summary['top_ip_addresses'], headers=["IP Address", "Access Attempts"]))
        print()

def print_logs(logs, limit=None):
    """Print the audit logs in a readable format"""
    # Filter out summary lines
    json_logs = [log for log in logs if not log.get('is_summary', False)]
    
    if limit:
        json_logs = json_logs[-limit:]
    
    rows = []
    for log in json_logs:
        timestamp = log.get('timestamp', '').replace('T', ' ').split('.')[0]
        status = "GRANTED" if log.get('access_granted') else "DENIED"
        user = log.get('user_email', 'Unknown')
        endpoint = log.get('endpoint', 'Unknown')
        ip = log.get('ip_address', 'Unknown')
        
        rows.append([timestamp, status, user, endpoint, ip])
    
    if rows:
        print(tabulate(rows, headers=["Timestamp", "Status", "User", "Endpoint", "IP Address"]))
    else:
        print("No matching log entries found.")

def main():
    parser = argparse.ArgumentParser(description='View and analyze security audit logs')
    
    # Filtering options
    parser.add_argument('--email', help='Filter by user email')
    parser.add_argument('--status', choices=['granted', 'denied'], help='Filter by access status')
    parser.add_argument('--endpoint', help='Filter by endpoint')
    parser.add_argument('--start-date', help='Filter by start date (YYYY-MM-DD)')
    parser.add_argument('--end-date', help='Filter by end date (YYYY-MM-DD)')
    
    # Display options
    parser.add_argument('--limit', type=int, default=20, help='Limit the number of log entries to display')
    parser.add_argument('--summary', action='store_true', help='Show summary statistics only')
    parser.add_argument('--all', action='store_true', help='Show all log entries (overrides --limit)')
    
    args = parser.parse_args()
    
    # Load and filter the logs
    logs = load_audit_logs()
    filtered_logs = filter_logs(logs, args)
    
    # Generate and print summary
    summary = generate_summary(filtered_logs)
    
    if args.summary:
        print_summary(summary)
    else:
        # Print the logs
        limit = None if args.all else args.limit
        print_logs(filtered_logs, limit)
        
        # Print a brief summary
        print(f"\nTotal matching entries: {summary['total_attempts']}")
        print(f"Granted: {summary['granted']}, Denied: {summary['denied']}")
        print(f"For full details, use --summary")

if __name__ == '__main__':
    main() 