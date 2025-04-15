#!/usr/bin/env python3
"""
Popular Pages Analyzer

This script analyzes access logs for web projects and creates reports showing
the most frequently accessed pages or URLs on your websites.

Usage:
    python page_analyzer.py

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

# Regular expression for extracting request URLs from access logs
# This pattern matches the common Apache/Nginx log format
REQUEST_PATTERN = r'"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) ([^"]*) HTTP/[0-9.]+"'

def ensure_dir(directory):
    """Create directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)

def parse_access_log(access_log_file):
    """
    Parse access log file and extract page requests.
    
    Returns:
        Counter: Counter object with page URLs and their counts
    """
    request_pattern = re.compile(REQUEST_PATTERN)
    page_counts = Counter()
    line_count = 0
    match_count = 0
    
    try:
        print(f"Opening access log file: '{access_log_file}'")
        with open(access_log_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line_count += 1
                if line_count <= 3:  # Print first few lines for debugging
                    print(f"Sample line {line_count}: {line[:100]}...")
                
                match = request_pattern.search(line)
                if match:
                    match_count += 1
                    method = match.group(1)
                    url = match.group(2)
                    
                    # Create a key with the method and URL
                    request_key = f'"{method} {url} HTTP/1.1"'
                    page_counts[request_key] += 1
        
        print(f"Processed {line_count} lines, found {match_count} page requests, unique URLs: {len(page_counts)}")
    except Exception as e:
        print(f"Error reading log file {access_log_file}: {e}")
        return Counter()
    
    return page_counts

def categorize_urls(page_counts):
    """
    Categorize URLs by type (image, document, API, etc.)
    
    Returns:
        dict: Dictionary with categories and their URL counts
    """
    categories = defaultdict(Counter)
    
    # Define patterns for different content types
    patterns = {
        "Image": r'\.(jpg|jpeg|png|gif|svg|webp|ico|bmp)(\?.*)?$',
        "Document": r'\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|rtf|csv)(\?.*)?$',
        "Media": r'\.(mp3|mp4|avi|mov|wmv|flv|ogg|webm|wav)(\?.*)?$',
        "Script": r'\.(js|jsx|ts|tsx)(\?.*)?$',
        "Style": r'\.(css|scss|sass|less)(\?.*)?$',
        "Data": r'\.(json|xml|rss|atom)(\?.*)?$',
        "Archive": r'\.(zip|rar|tar|gz|7z)(\?.*)?$',
        "Font": r'\.(ttf|otf|woff|woff2|eot)(\?.*)?$',
        "API": r'(/api/|/rest/|/graphql)',
        "Static": r'(/static/|/assets/|/dist/|/build/)',
    }
    
    # Categorize each URL
    for request_key, count in page_counts.items():
        # Extract URL from the request key (e.g., "GET /path/to/file.jpg HTTP/1.1")
        match = re.search(r'"[A-Z]+ (.*?) HTTP', request_key)
        if not match:
            continue
            
        url = match.group(1)
        categorized = False
        
        # Check for each category
        for category, pattern in patterns.items():
            if re.search(pattern, url, re.IGNORECASE):
                categories[category][request_key] = count
                categorized = True
                break
        
        # If not matched any specific category, put in Page
        if not categorized:
            categories["Page"][request_key] = count
    
    return categories

def generate_pages_report(project_name, page_counts, categories, output_dir):
    """Generate an HTML report of most popular pages."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"pages_report_{today}.html")
    
    # Sort pages by frequency (highest first)
    sorted_pages = page_counts.most_common()
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Popular Pages Report for {project_name} - {today}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .page-count {{ font-weight: bold; }}
        .page-item {{ margin-bottom: 10px; border-left: 4px solid #009900; padding-left: 10px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ text-align: left; padding: 8px; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        tr:hover {{ background-color: #f2f2f2; }}
        .nav {{ margin-bottom: 20px; padding: 10px; background-color: #f5f5f5; }}
        .tabs {{ display: flex; margin-bottom: 20px; border-bottom: 1px solid #ddd; }}
        .tab {{ padding: 10px 15px; cursor: pointer; margin-right: 5px; }}
        .tab.active {{ background-color: #f0f0f0; border: 1px solid #ddd; border-bottom: none; }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}
    </style>
    <script>
        function showTab(tabId) {{
            // Hide all tab contents
            const tabContents = document.getElementsByClassName('tab-content');
            for (let i = 0; i < tabContents.length; i++) {{
                tabContents[i].classList.remove('active');
            }}
            
            // Deactivate all tabs
            const tabs = document.getElementsByClassName('tab');
            for (let i = 0; i < tabs.length; i++) {{
                tabs[i].classList.remove('active');
            }}
            
            // Show the selected tab content
            document.getElementById(tabId).classList.add('active');
            
            // Activate the selected tab
            document.getElementById('tab-' + tabId).classList.add('active');
        }}
    </script>
</head>
<body>
    <div class="nav">
        <a href="index.html">← Dashboard</a> |
        <a href="../index.html">← {project_name} Summary</a>
    </div>

    <h1>Popular Pages Report for {project_name}</h1>
    <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <h2>Summary</h2>
    <p>Total unique URLs: {len(page_counts)}</p>
    <p>Total requests: {sum(page_counts.values())}</p>
    
    <div class="tabs">
        <div id="tab-all-pages" class="tab active" onclick="showTab('all-pages')">All Requests</div>
"""

    # Add tabs for each category
    for category in sorted(categories.keys()):
        category_id = category.lower().replace(' ', '-')
        html_content += f"""
        <div id="tab-{category_id}" class="tab" onclick="showTab('{category_id}')">{category} ({len(categories[category])})</div>"""
    
    html_content += """
    </div>
    
    <div id="all-pages" class="tab-content active">
        <h2>All Page Requests</h2>
        <table>
            <tr>
                <th>Count</th>
                <th>Request</th>
            </tr>
"""
    
    # Add rows for all pages
    for request_key, count in sorted_pages[:1000]:  # Limit to top 1000
        html_content += f"""
            <tr>
                <td>{count}</td>
                <td>{request_key}</td>
            </tr>"""
    
    html_content += """
        </table>
    </div>
"""
    
    # Add tab content for each category
    for category in sorted(categories.keys()):
        category_id = category.lower().replace(' ', '-')
        category_pages = categories[category].most_common()
        
        html_content += f"""
    <div id="{category_id}" class="tab-content">
        <h2>{category} Requests</h2>
        <table>
            <tr>
                <th>Count</th>
                <th>Request</th>
            </tr>
"""
        
        # Add rows for category pages
        for request_key, count in category_pages[:500]:  # Limit to top 500 per category
            html_content += f"""
            <tr>
                <td>{count}</td>
                <td>{request_key}</td>
            </tr>"""
        
        html_content += """
        </table>
    </div>
"""
    
    html_content += """
</body>
</html>
"""
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return report_file

def generate_plain_text_report(project_name, page_counts, output_dir):
    """Generate a plain text report of page access counts."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"pages_report_{today}.txt")
    
    # Sort pages by frequency (highest first)
    sorted_pages = page_counts.most_common()
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f"Popular Pages Report for {project_name}\n")
        f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"Total unique URLs: {len(page_counts)}\n")
        f.write(f"Total requests: {sum(page_counts.values())}\n\n")
        f.write("Top URLs:\n")
        f.write("-" * 30 + "\n")
        
        # Add top pages to the file
        for request_key, count in sorted_pages:
            f.write(f"{count:6d} - {request_key}\n")
    
    return report_file

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
        page_counts = parse_access_log(access_log_file)
        
        if not page_counts:
            print(f"No page requests found or couldn't parse log for {project_name}")
            continue
        
        # Categorize URLs
        categories = categorize_urls(page_counts)
        
        # Generate HTML report
        html_report_file = generate_pages_report(project_name, page_counts, categories, date_dir)
        print(f"Generated HTML pages report for {project_name}: {html_report_file}")
        
        # Generate plain text report
        text_report_file = generate_plain_text_report(project_name, page_counts, date_dir)
        print(f"Generated text pages report for {project_name}: {text_report_file}")
        
        # Create copies in the project directory for the summary
        html_report_basename = os.path.basename(html_report_file)
        text_report_basename = os.path.basename(text_report_file)
        shutil.copy(html_report_file, os.path.join(project_dir, html_report_basename))
        shutil.copy(text_report_file, os.path.join(project_dir, text_report_basename))
    
    print("Popular pages analysis completed successfully.")

if __name__ == "__main__":
    main()
