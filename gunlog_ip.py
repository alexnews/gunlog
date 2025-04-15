#!/usr/bin/env python3
"""
IP Access Log Analyzer

This script analyzes access logs for web projects and creates reports showing
the most frequent IP addresses accessing your websites.

Usage:
    python gunlog_ip.py

Requirements:
    - Configuration file (config.py) with path settings
    - CSV file with project information
    - Access to log files specified in the CSV
"""

import os
import re
import csv
import datetime
import shutil
from collections import Counter, defaultdict

# Import configuration
try:
    from config import PROJECTS_CSV, OUTPUT_BASE_DIR, DATE_FORMAT
except ImportError:
    print("Error: config.py file not found! Please create it with the required settings.")
    exit(1)

# IP address regular expression pattern
IP_PATTERN = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

def ensure_dir(directory):
    """Create directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)

def parse_access_log(access_log_file):
    """
    Parse access log file and extract IP addresses.
    
    Returns:
        Counter: Counter object with IP addresses and their counts
    """
    ip_pattern = re.compile(IP_PATTERN)
    ip_counts = Counter()
    line_count = 0
    match_count = 0
    
    try:
        print(f"Opening access log file: '{access_log_file}'")
        with open(access_log_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line_count += 1
                if line_count <= 3:  # Print first few lines for debugging
                    print(f"Sample line {line_count}: {line[:100]}...")
                
                match = ip_pattern.search(line)
                if match:
                    match_count += 1
                    ip = match.group(1)
                    ip_counts[ip] += 1
        
        print(f"Processed {line_count} lines, found {match_count} IP addresses, unique IPs: {len(ip_counts)}")
    except Exception as e:
        print(f"Error reading log file {access_log_file}: {e}")
        return Counter()
    
    return ip_counts

def generate_ip_report(project_name, ip_counts, output_dir):
    """Generate an HTML report of IP access counts."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"ip_report_{today}.html")
    
    # Sort IPs by frequency (highest first)
    sorted_ips = ip_counts.most_common()
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>IP Access Report for {project_name} - {today}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        .ip-count {{ font-weight: bold; }}
        .ip-item {{ margin-bottom: 10px; border-left: 4px solid #0066cc; padding-left: 10px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ text-align: left; padding: 8px; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        tr:hover {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>IP Access Report for {project_name}</h1>
    <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <h2>Summary</h2>
    <p>Total unique IP addresses: {len(ip_counts)}</p>
    <p>Total accesses: {sum(ip_counts.values())}</p>
    
    <h2>Top IP Addresses</h2>
    <table>
        <tr>
            <th>Count</th>
            <th>IP Address</th>
        </tr>
"""
    
    # Add top 1000 IPs to the table
    for ip, count in sorted_ips[:1000]:
        html_content += f"""
        <tr>
            <td>{count}</td>
            <td>{ip}</td>
        </tr>
"""
    
    html_content += """
    </table>
</body>
</html>
"""
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return report_file

def generate_plain_text_report(project_name, ip_counts, output_dir):
    """Generate a plain text report of IP access counts."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"ip_report_{today}.txt")
    
    # Sort IPs by frequency (highest first)
    sorted_ips = ip_counts.most_common()
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f"IP Access Report for {project_name}\n")
        f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"Total unique IP addresses: {len(ip_counts)}\n")
        f.write(f"Total accesses: {sum(ip_counts.values())}\n\n")
        f.write("Top IP Addresses:\n")
        f.write("-" * 30 + "\n")
        
        # Add top IPs to the file
        for ip, count in sorted_ips:
            f.write(f"{count:6d} - {ip}\n")
    
    return report_file

def generate_project_summary(project_name, daily_reports, output_dir):
    """Generate a summary HTML page for the project with links to daily IP reports."""
    summary_file = os.path.join(output_dir, "ip_index.html")
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>IP Access Summary for {project_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        ul {{ list-style-type: none; padding: 0; }}
        li {{ margin: 10px 0; }}
        a {{ color: #0066cc; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <h1>IP Access Summary for {project_name}</h1>
    <p>Last updated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <h2>Daily Reports</h2>
    <ul>
"""
    
    # Sort reports by date (newest first)
    sorted_reports = sorted(daily_reports, reverse=True)
    
    for report in sorted_reports:
        report_date = report.split('_')[-1].split('.')[0]
        formatted_date = f"{report_date[:4]}-{report_date[4:6]}-{report_date[6:]}"
        html_content += f"""
        <li><a href="{report_date}/{os.path.basename(report)}">{formatted_date}</a></li>
"""
    
    html_content += """
    </ul>
</body>
</html>
"""
    
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return summary_file

def main():
    """Main function to process logs and generate reports."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    projects_data = []
    
    # Read projects from CSV
    try:
        with open(PROJECTS_CSV, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile, skipinitialspace=True)
            for row in reader:
                # Clean any whitespace from all values in the row
                cleaned_row = {k: v.strip() if isinstance(v, str) else v for k, v in row.items()}
                projects_data.append(cleaned_row)
    except Exception as e:
        print(f"Error reading projects CSV: {e}")
        return
    
    processed_projects = []
    
    # Process each project
    for project_data in projects_data:
        project_name = project_data.get('project', '').strip().replace('.', '_')
        access_log_file = project_data.get('log_file', '').strip()
        
        if not project_name or not access_log_file:
            print(f"Missing project name or access log file: {project_data}")
            continue
        
        processed_projects.append(project_data['project'])
        
        # Create project directory
        project_dir = os.path.join(OUTPUT_BASE_DIR, project_name)
        ensure_dir(project_dir)
        
        # Create date-specific directory
        date_dir = os.path.join(project_dir, today)
        ensure_dir(date_dir)
        
        # Parse access log
        ip_counts = parse_access_log(access_log_file)
        
        if not ip_counts:
            print(f"No IP addresses found or couldn't parse log for {project_name}")
            continue
        
        # Generate HTML report
        html_report_file = generate_ip_report(project_name, ip_counts, date_dir)
        print(f"Generated HTML IP report for {project_name}: {html_report_file}")
        
        # Generate plain text report
        text_report_file = generate_plain_text_report(project_name, ip_counts, date_dir)
        print(f"Generated text IP report for {project_name}: {text_report_file}")
        
        # Create copies in the project directory for the summary
        html_report_basename = os.path.basename(html_report_file)
        text_report_basename = os.path.basename(text_report_file)
        shutil.copy(html_report_file, os.path.join(project_dir, html_report_basename))
        shutil.copy(text_report_file, os.path.join(project_dir, text_report_basename))
        
        # Get all daily HTML reports for this project
        daily_reports = []
        for filename in os.listdir(project_dir):
            if filename.startswith('ip_report_') and filename.endswith('.html'):
                daily_reports.append(filename)
        
        # Generate project summary
        summary_file = generate_project_summary(project_name, daily_reports, project_dir)
        print(f"Generated IP access summary for {project_name}: {summary_file}")
    
    print("IP access log analysis completed successfully.")

if __name__ == "__main__":
    main()
