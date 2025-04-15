#!/usr/bin/env python3
"""
GunLog Error Analyzer with Index Generation

This script analyzes error logs for web projects and generates daily reports.
It also creates index pages for each date directory to provide easy access to all
analytics reports.

Usage:
    python gunlog_analyzer.py

Requirements:
    - Configuration file (config.py) with path settings
    - CSV file with project information 
    - Access to log files specified in the CSV
"""

import os
import re
import csv
import glob
import datetime
import shutil
from collections import defaultdict

# Import configuration
try:
    from config import PROJECTS_CSV, OUTPUT_BASE_DIR, DATE_FORMAT, ERROR_PATTERN
except ImportError:
    print("Error: config.py file not found! Please create it with the required settings.")
    exit(1)

def ensure_dir(directory):
    """Create directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)

def parse_error_log(error_log_file):
    """
    Parse error log file and extract error information.
    
    Returns:
        dict: Dictionary with error types as keys and lists of error instances as values
    """
    error_pattern = re.compile(ERROR_PATTERN)
    errors = defaultdict(list)
    line_count = 0
    match_count = 0
    
    try:
        print(f"Opening error log file: '{error_log_file}'")
        with open(error_log_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line_count += 1
                if line_count <= 5:  # Print first few lines for debugging
                    print(f"Sample line {line_count}: {line[:100]}...")
                
                match = error_pattern.search(line)
                if match:
                    match_count += 1
                    error_msg = match.group(1).strip()
                    file_path = match.group(2).strip()
                    line_num = match.group(3).strip()
                    
                    error_key = f"{error_msg} in {os.path.basename(file_path)} on line {line_num}"
                    error_detail = f"{error_msg} in {file_path} on line {line_num}"
                    errors[error_key].append(error_detail)
        
        print(f"Processed {line_count} lines, found {match_count} PHP errors, unique errors: {len(errors)}")
        
        # If no errors found but file exists, check regex pattern
        if match_count == 0 and line_count > 0:
            print(f"WARNING: No errors matched the pattern: {ERROR_PATTERN}")
            print("Check your config.py ERROR_PATTERN setting!")
            
            # Try some common patterns to see if they match
            test_patterns = [
                r'PHP (?:Warning|Notice|Error|Fatal error|Parse error):\s+(.*?) in (.*?) on line (\d+)',
                r'(?:Warning|Notice|Error|Fatal error|Parse error):\s+(.*?) in (.*?) on line (\d+)',
                r'\[(.*?)\] \[error\]'
            ]
            
            # Reopen the file and try different patterns
            with open(error_log_file, 'r', encoding='utf-8', errors='replace') as f:
                sample_lines = [next(f) for _ in range(10) if f]
                
            for i, pattern in enumerate(test_patterns):
                print(f"\nTrying pattern {i+1}: {pattern}")
                test_regex = re.compile(pattern)
                for line in sample_lines:
                    match = test_regex.search(line)
                    if match:
                        print(f"Pattern {i+1} MATCHED on line: {line[:100]}...")
                        print(f"Match groups: {match.groups()}")
                        break
    except Exception as e:
        print(f"Error reading log file {error_log_file}: {e}")
        return {}
    
    return errors

def generate_error_report(project_name, errors, output_dir):
    """Generate an HTML report of errors."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"error_report_{today}.html")
    
    # Sort errors by frequency (highest first)
    sorted_errors = sorted(errors.items(), key=lambda x: len(x[1]), reverse=True)
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Error Report for {project_name} - {today}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        .error-count {{ font-weight: bold; }}
        .error-item {{ margin-bottom: 20px; border-left: 4px solid #cc0000; padding-left: 10px; }}
        .error-example {{ font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px; }}
        .nav {{ margin-bottom: 20px; padding: 10px; background-color: #f5f5f5; }}
    </style>
</head>
<body>
    <div class="nav">
        <a href="index.html">← Dashboard</a> |
        <a href="../index.html">← {project_name} Summary</a>
    </div>

    <h1>Error Report for {project_name}</h1>
    <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <h2>Summary</h2>
    <p>Total unique errors: {len(errors)}</p>
    <p>Total error occurrences: {sum(len(instances) for instances in errors.values())}</p>
    
    <h2>Error List</h2>
"""
    
    for error_key, instances in sorted_errors:
        html_content += f"""
    <div class="error-item">
        <p class="error-count">{len(instances)} - {error_key}</p>
        <div class="error-example">Example: {instances[0]}</div>
    </div>
"""
    
    html_content += """
</body>
</html>
"""
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return report_file

def generate_project_summary(project_name, daily_reports, output_dir):
    """Generate a summary HTML page for the project with links to daily reports."""
    summary_file = os.path.join(output_dir, "index.html")
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Project Summary for {project_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        ul {{ list-style-type: none; padding: 0; }}
        li {{ margin: 10px 0; }}
        a {{ color: #0066cc; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .nav {{ margin-bottom: 20px; padding: 10px; background-color: #f5f5f5; }}
    </style>
</head>
<body>
    <div class="nav">
        <a href="../index.html">← All Projects</a>
    </div>

    <h1>Project Summary for {project_name}</h1>
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
        <li><a href="{report_date}/index.html">{formatted_date} Dashboard</a></li>
"""
    
    html_content += """
    </ul>
</body>
</html>
"""
    
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return summary_file

def generate_main_index(projects, output_base_dir):
    """Generate a main index HTML page with links to all project summaries."""
    index_file = os.path.join(output_base_dir, "index.html")
    
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>GunLog Web Project Analysis</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #333; }
        ul { list-style-type: none; padding: 0; }
        li { margin: 10px 0; }
        a { color: #0066cc; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .dashboard { display: flex; flex-wrap: wrap; gap: 20px; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 15px; width: 200px; }
        .card h3 { margin-top: 0; color: #0066cc; }
    </style>
</head>
<body>
    <h1>GunLog Web Project Analysis</h1>
    <p>Last updated: """ + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
    
    <h2>Projects</h2>
    <div class="dashboard">
"""
    
    for project in sorted(projects):
        project_name = project.replace('.', '_')
        html_content += f"""
        <div class="card">
            <h3>{project}</h3>
            <a href="{project_name}/index.html">View Reports</a>
        </div>
"""
    
    html_content += """
    </div>
</body>
</html>
"""
    
    with open(index_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return index_file

def create_daily_index(project_dir, date_dir):
    """
    Create an index.html file in the date directory that links to all analytics reports.
    
    Args:
        project_dir: Path to the project directory
        date_dir: Path to the date directory
    
    Returns:
        str: Path to the generated index file
    """
    project_name = os.path.basename(project_dir).replace('_', '.')
    date_str = os.path.basename(date_dir)
    formatted_date = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:]}"
    
    # Get all report files in the date directory
    report_files = []
    for ext in ['html', 'txt', 'csv', 'json', 'xml']:
        report_files.extend(glob.glob(os.path.join(date_dir, f"*_report_*.{ext}")))
    
    # Extract report types
    report_types = {}
    for report_file in report_files:
        basename = os.path.basename(report_file)
        match = re.match(r'(\w+)_report_', basename)
        if match:
            report_type = match.group(1)
            if report_type not in report_types:
                report_types[report_type] = []
            report_types[report_type].append(report_file)
    
    # Create index.html
    index_file = os.path.join(date_dir, "index.html")
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Analytics Dashboard for {project_name} - {formatted_date}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .dashboard {{ display: flex; flex-wrap: wrap; gap: 20px; }}
        .card {{ border: 1px solid #ddd; border-radius: 8px; padding: 15px; width: 300px; }}
        .card h3 {{ margin-top: 0; color: #0066cc; }}
        .card-content {{ margin-top: 10px; }}
        ul {{ list-style-type: none; padding: 0; margin: 0; }}
        li {{ margin-bottom: 8px; }}
        a {{ color: #0066cc; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .nav {{ margin-bottom: 20px; padding: 10px; background-color: #f5f5f5; }}
        .description {{ color: #666; font-size: 0.9em; margin-top: 5px; }}
    </style>
</head>
<body>
    <div class="nav">
        <a href="../../index.html">← All Projects</a> |
        <a href="../index.html">← {project_name} Summary</a>
    </div>
    
    <h1>Analytics Dashboard for {project_name}</h1>
    <p>Date: {formatted_date}</p>
    
    <div class="dashboard">
"""
    
    # Report type descriptions
    descriptions = {
        "error": "Error log analysis showing PHP errors and warnings",
        "ip": "Analysis of visitor IP addresses and their frequency",
        "traffic": "Website traffic analysis and visitor statistics",
        "performance": "Website performance metrics and loading times",
        "security": "Security-related events and potential threats",
        "seo": "Search engine optimization metrics and rankings",
        "content": "Content analysis and most viewed pages"
    }
    
    # Add cards for each report type
    for report_type, files in report_types.items():
        html_content += f"""
        <div class="card">
            <h3>{report_type.title()} Analytics</h3>
            <p class="description">{descriptions.get(report_type, "Analysis report")}</p>
            <div class="card-content">
                <ul>
"""
        
        for file in files:
            file_basename = os.path.basename(file)
            file_ext = os.path.splitext(file_basename)[1]
            
            # Create a friendly label based on the file extension
            if file_ext == '.html':
                label = 'HTML Report'
            elif file_ext == '.txt':
                label = 'Text Report'
            elif file_ext == '.csv':
                label = 'CSV Data'
            elif file_ext == '.json':
                label = 'JSON Data'
            elif file_ext == '.xml':
                label = 'XML Report'
            else:
                label = file_basename
            
            html_content += f"""
                    <li><a href="{file_basename}">{label}</a></li>
"""
        
        html_content += """
                </ul>
            </div>
        </div>
"""
    
    # If there are no reports yet, show a message
    if not report_types:
        html_content += """
        <div class="card">
            <h3>No Reports Available</h3>
            <p>No analytics reports have been generated for this date yet.</p>
        </div>
"""
    
    html_content += """
    </div>
</body>
</html>
"""
    
    with open(index_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return index_file

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
        error_log_file = project_data.get('error_log_file', '').strip()
        
        if not project_name or not error_log_file:
            print(f"Missing project name or error log file: {project_data}")
            continue
        
        processed_projects.append(project_data['project'])
        
        # Create project directory
        project_dir = os.path.join(OUTPUT_BASE_DIR, project_name)
        ensure_dir(project_dir)
        
        # Create date-specific directory
        date_dir = os.path.join(project_dir, today)
        ensure_dir(date_dir)
        
        # Parse error log
        errors = parse_error_log(error_log_file)
        
        if not errors:
            print(f"No errors found or couldn't parse log for {project_name}")
            continue
        
        # Generate error report
        report_file = generate_error_report(project_name, errors, date_dir)
        print(f"Generated error report for {project_name}: {report_file}")
        
        # Create a copy in the project directory for the summary
        report_basename = os.path.basename(report_file)
        shutil.copy(report_file, os.path.join(project_dir, report_basename))
        
        # Create daily index page
        index_file = create_daily_index(project_dir, date_dir)
        print(f"Generated daily index for {project_name}: {index_file}")
        
        # Get all daily reports for this project
        daily_reports = []
        for filename in os.listdir(project_dir):
            if filename.startswith('error_report_') and filename.endswith('.html'):
                daily_reports.append(filename)
        
        # Generate project summary
        summary_file = generate_project_summary(project_name, daily_reports, project_dir)
        print(f"Generated project summary for {project_name}: {summary_file}")
    
    # Generate main index
    if processed_projects:
        main_index = generate_main_index(processed_projects, OUTPUT_BASE_DIR)
        print(f"Generated main index: {main_index}")
    
    print("Error log analysis completed successfully.")

if __name__ == "__main__":
    main()
