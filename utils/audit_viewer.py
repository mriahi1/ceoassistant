#!/usr/bin/env python3
"""
Audit Log Viewer Utility

This script provides a command-line interface for viewing and analyzing 
access audit logs, focusing on email-based access control.
"""

import argparse
import json
import datetime
import os
import sys
from tabulate import tabulate
from dateutil.parser import parse as parse_date

# Add parent directory to import path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.audit_logger import get_access_logs, get_access_stats

def format_timestamp(timestamp_str):
    """Format ISO timestamp to a more readable format"""
    try:
        dt = datetime.datetime.fromisoformat(timestamp_str)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return timestamp_str

def print_logs(logs, format_type="table"):
    """Print logs in the specified format"""
    if not logs:
        print("No log entries found matching the criteria.")
        return
        
    if format_type == "json":
        print(json.dumps(logs, indent=2))
        return
        
    # Format as table
    table_data = []
    for log in logs:
        table_data.append([
            format_timestamp(log.get('timestamp')),
            log.get('user_email', 'unknown'),
            "✅ GRANTED" if log.get('access_granted') else "❌ DENIED",
            log.get('endpoint', 'unknown'),
            log.get('ip_address', 'unknown'),
            log.get('reason', '')
        ])
        
    headers = ["Timestamp", "User Email", "Access", "Endpoint", "IP Address", "Reason"]
    print(tabulate(table_data, headers=headers, tablefmt="pretty"))
    
def print_stats(stats):
    """Print statistics about access attempts"""
    print("\n=== Access Statistics ===")
    print(f"Total access attempts: {stats['total_attempts']}")
    print(f"Access granted: {stats['granted']} ({stats['granted']/max(stats['total_attempts'], 1)*100:.1f}%)")
    print(f"Access denied: {stats['denied']} ({stats['denied']/max(stats['total_attempts'], 1)*100:.1f}%)")
    
    # Print endpoint statistics
    print("\n=== Endpoint Statistics ===")
    endpoint_data = []
    for endpoint, data in stats['endpoints'].items():
        endpoint_data.append([
            endpoint,
            data['total'],
            data['granted'],
            data['denied'],
            f"{data['denied']/max(data['total'], 1)*100:.1f}%"
        ])
    
    endpoint_headers = ["Endpoint", "Total", "Granted", "Denied", "Denial Rate"]
    print(tabulate(endpoint_data, headers=endpoint_headers, tablefmt="pretty"))
    
    # Print user statistics
    print("\n=== User Statistics ===")
    user_data = []
    for user, data in stats['users'].items():
        user_data.append([
            user,
            data['total'],
            data['granted'],
            data['denied'],
            f"{data['denied']/max(data['total'], 1)*100:.1f}%"
        ])
    
    user_headers = ["User", "Total", "Granted", "Denied", "Denial Rate"]
    print(tabulate(user_data, headers=user_headers, tablefmt="pretty"))

def main():
    """Main function for the audit viewer utility"""
    parser = argparse.ArgumentParser(description="View and analyze access audit logs")
    
    # Filter arguments
    parser.add_argument("--email", help="Filter logs by user email")
    parser.add_argument("--endpoint", help="Filter logs by endpoint")
    parser.add_argument("--granted", action="store_true", help="Show only granted access")
    parser.add_argument("--denied", action="store_true", help="Show only denied access")
    parser.add_argument("--start-date", help="Filter by start date (YYYY-MM-DD or ISO format)")
    parser.add_argument("--end-date", help="Filter by end date (YYYY-MM-DD or ISO format)")
    
    # Output format
    parser.add_argument("--format", choices=["table", "json"], default="table", 
                      help="Output format (default: table)")
    parser.add_argument("--stats", action="store_true", 
                      help="Show statistics instead of individual log entries")
    
    args = parser.parse_args()
    
    # Convert date strings to ISO format if provided
    start_date = None
    end_date = None
    
    if args.start_date:
        try:
            start_date = parse_date(args.start_date).isoformat()
        except ValueError:
            print(f"Error: Invalid start date format: {args.start_date}")
            return 1
            
    if args.end_date:
        try:
            end_date = parse_date(args.end_date).isoformat()
        except ValueError:
            print(f"Error: Invalid end date format: {args.end_date}")
            return 1
    
    # Determine access granted filter
    granted = None
    if args.granted and not args.denied:
        granted = True
    elif args.denied and not args.granted:
        granted = False
    
    # Get logs
    logs = get_access_logs(
        email=args.email,
        endpoint=args.endpoint,
        granted=granted,
        start_date=start_date,
        end_date=end_date
    )
    
    # Output based on format and stats flag
    if args.stats:
        stats = get_access_stats(start_date=start_date, end_date=end_date)
        print_stats(stats)
    else:
        print_logs(logs, format_type=args.format)
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 