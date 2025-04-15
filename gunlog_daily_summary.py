#!/usr/bin/env python3
"""
Fixed Daily Error Counter

This script counts errors by day in PHP error logs, using the same error detection
logic as the successful GunLog Error Analyzer.

Usage:
    python fixed_daily_error_counter.py

Requirements:
    - Configuration file (config.py) with path settings
    - CSV file with project information
    - Access to error log files specified in the CSV
"""

import os
import re
import csv
import datetime
import calendar
import shutil
from collections import defaultdict, Counter

# Import configuration
try:
    from config import PROJECTS_CSV, OUTPUT_BASE_DIR, DATE_FORMAT
except ImportError:
    print("Error: config.py file not found! Please create it with the required settings.")
    exit(1)

# Regular expression patterns
DATE_PATTERN = r'\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})\]'
ERROR_PATTERN = r'PHP (?:Warning|Notice|Error|Fatal error|Parse error):'

def ensure_dir(directory):
    """Create directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)

def extract_date_from_log_line(line):
    """
    Extract date from log line using the standard Apache/PHP log format.
    
    Args:
        line: Log line to extract date from
        
    Returns:
        str: Date in format "YYYY-MM-DD" or None if extraction fails
    """
    # Look for the standard log date format [DD/MMM/YYYY:HH:MM:SS +ZZZZ]
    match = re.search(DATE_PATTERN, line)
    if match:
        day = match.group(1)
        month_str = match.group(2)
        year = match.group(3)
        
        # Convert month name to number
        month_names = {
            'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
            'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
        }
        month = month_names.get(month_str, 1)
        
        return f"{year}-{month:02d}-{day}"
    
    # If the standard pattern fails, try a more generic approach to find dates
    # Look for date patterns in the format YYYY-MM-DD
    date_match = re.search(r'(\d{4})-(\d{2})-(\d{2})', line)
    if date_match:
        return date_match.group(0)
    
    # Look for date patterns in the format DD/MM/YYYY
    date_match = re.search(r'(\d{2})/(\d{2})/(\d{4})', line)
    if date_match:
        day = date_match.group(1)
        month = date_match.group(2)
        year = date_match.group(3)
        return f"{year}-{month}-{day}"
    
    # Unable to extract date
    return None

def count_errors_by_day(error_log_file):
    """
    Count PHP errors by day in an error log file.
    
    Args:
        error_log_file: Path to the error log file
        
    Returns:
        Counter: Counter object with dates as keys and error counts as values
    """
    daily_error_counts = Counter()
    total_lines = 0
    error_lines = 0
    dated_errors = 0
    
    try:
        print(f"Processing error log: {error_log_file}")
        
        # Check if file exists and is readable
        if not os.path.isfile(error_log_file):
            print(f"ERROR: File {error_log_file} not found or is not a file")
            return daily_error_counts
        
        if not os.access(error_log_file, os.R_OK):
            print(f"ERROR: No read permission for {error_log_file}")
            return daily_error_counts
        
        # Print file size
        file_size = os.path.getsize(error_log_file)
        print(f"File size: {file_size:,} bytes")
        
        # Sample the file to detect format (first 5 lines)
        with open(error_log_file, 'r', encoding='utf-8', errors='replace') as f:
            sample_lines = []
            for i in range(5):
                try:
                    line = next(f)
                    sample_lines.append(line)
                except StopIteration:
                    break
        
        print(f"Sample of first {len(sample_lines)} lines:")
        for i, line in enumerate(sample_lines):
            print(f"  Line {i+1}: {line[:100]}..." if len(line) > 100 else f"  Line {i+1}: {line}")
        
        # Process the file
        with open(error_log_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                total_lines += 1
                
                # Skip empty lines
                if not line.strip():
                    continue
                
                # Check if this is an error line
                if re.search(ERROR_PATTERN, line):
                    error_lines += 1
                    
                    # Extract date
                    date = extract_date_from_log_line(line)
                    if date:
                        daily_error_counts[date] += 1
                        dated_errors += 1
                
                # Print progress for large files
                if total_lines % 100000 == 0:
                    print(f"  Processed {total_lines:,} lines, found {error_lines:,} errors...")
        
        print(f"Completed processing {total_lines:,} lines")
        print(f"Found {error_lines:,} error lines, of which {dated_errors:,} had extractable dates")
        
        # If we found errors but no dates, try a fallback approach
        if error_lines > 0 and dated_errors == 0:
            print("WARNING: Found errors but couldn't extract dates. Using fallback approach...")
            
            # Use file modification time as fallback
            mtime = os.path.getmtime(error_log_file)
            fallback_date = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d")
            daily_error_counts[fallback_date] = error_lines
            print(f"  Using file modification date ({fallback_date}) for all {error_lines} errors")
        
        # Display sample of daily counts
        if daily_error_counts:
            print("Sample of daily error counts:")
            for date, count in sorted(daily_error_counts.items())[:5]:
                print(f"  {date}: {count:,} errors")
            if len(daily_error_counts) > 5:
                print(f"  ... and {len(daily_error_counts) - 5} more days")
        else:
            print("No errors found with dates")
    
    except Exception as e:
        print(f"ERROR processing {error_log_file}: {str(e)}")
    
    return daily_error_counts

def generate_daily_error_report(project_name, daily_error_counts, output_dir):
    """
    Generate daily error report for a project.
    
    Args:
        project_name: Name of the project
        daily_error_counts: Counter with daily error counts
        output_dir: Directory to save the report
        
    Returns:
        str: Path to the generated report
    """
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"{project_name}_daily_error_counts.html")
    
    # Get all dates
    all_dates = sorted(daily_error_counts.keys())
    
    if not all_dates:
        print(f"No error dates found for {project_name}")
        all_dates = [today]  # Add current date as fallback
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Daily Error Counts for {project_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .chart-container {{ height: 400px; width: 100%; margin-top: 20px; }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>Daily Error Counts for {project_name}</h1>
    <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="chart-container">
        <canvas id="errorChart"></canvas>
    </div>
    
    <table>
        <tr>
            <th>Date</th>
            <th>Error Count</th>
        </tr>
""")
        
        # Add rows for each date
        for date in all_dates:
            error_count = daily_error_counts.get(date, 0)
            f.write(f"""
        <tr>
            <td>{date}</td>
            <td>{error_count:,}</td>
        </tr>""")
        
        # Add chart and close HTML
        f.write(f"""
    </table>
    
    <script>
        const errorCtx = document.getElementById('errorChart').getContext('2d');
        const errorChart = new Chart(errorCtx, {{
            type: 'line',
            data: {{
                labels: [{', '.join([f"'{date}'" for date in all_dates])}],
                datasets: [{{
                    label: 'Daily Error Counts',
                    data: [{', '.join([str(daily_error_counts.get(date, 0)) for date in all_dates])}],
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    borderColor: 'rgba(255, 99, 132, 1)',
                    borderWidth: 1,
                    tension: 0.1
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        title: {{
                            display: true,
                            text: 'Number of Errors'
                        }}
                    }},
                    x: {{
                        title: {{
                            display: true,
                            text: 'Date'
                        }}
                    }}
                }},
                plugins: {{
                    title: {{
                        display: true,
                        text: 'Daily Error Counts'
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>""")
    
    # Generate text report
    text_report_file = os.path.join(output_dir, f"{project_name}_daily_error_counts.txt")
    with open(text_report_file, 'w', encoding='utf-8') as f:
        f.write(f"Daily Error Counts for {project_name}\n")
        f.write("=" * 50 + "\n")
        f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("Date         | Errors\n")
        f.write("-" * 25 + "\n")
        
        for date in all_dates:
            error_count = daily_error_counts.get(date, 0)
            f.write(f"{date} | {error_count:,}\n")
    
    print(f"Generated HTML error report: {report_file}")
    print(f"Generated text error report: {text_report_file}")
    
    return report_file

def generate_monthly_error_summary(project_name, daily_error_counts, output_dir):
    """
    Generate monthly error summary for a project.
    
    Args:
        project_name: Name of the project
        daily_error_counts: Counter with daily error counts
        output_dir: Directory to save the report
        
    Returns:
        str: Path to the generated report
    """
    # Aggregate daily counts into monthly counts
    monthly_error_counts = defaultdict(int)
    
    for date, count in daily_error_counts.items():
        if len(date) >= 7:  # Make sure date is valid format
            month = date[:7]  # Extract YYYY-MM
            monthly_error_counts[month] += count
    
    # Get all months
    all_months = sorted(monthly_error_counts.keys())
    
    if not all_months:
        print(f"No monthly data found for {project_name}")
        current_month = datetime.datetime.now().strftime("%Y-%m")
        all_months = [current_month]
        monthly_error_counts[current_month] = 0
    
    # Generate monthly report
    monthly_report_file = os.path.join(output_dir, f"{project_name}_monthly_error_summary.html")
    
    with open(monthly_report_file, 'w', encoding='utf-8') as f:
        f.write(f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Monthly Error Summary for {project_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .chart-container {{ height: 400px; width: 100%; margin-top: 20px; }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>Monthly Error Summary for {project_name}</h1>
    <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="chart-container">
        <canvas id="monthlySummaryChart"></canvas>
    </div>
    
    <table>
        <tr>
            <th>Month</th>
            <th>Error Count</th>
        </tr>
""")
        
        # Add rows for each month
        for month in all_months:
            error_count = monthly_error_counts.get(month, 0)
            
            # Format month for display (YYYY-MM to Month YYYY)
            try:
                year, month_num = month.split('-')
                month_name = calendar.month_name[int(month_num)]
            except:
                month_name = "Unknown"
                year = "Unknown"
            
            f.write(f"""
        <tr>
            <td>{month_name} {year}</td>
            <td>{error_count:,}</td>
        </tr>""")
        
        # Prepare month labels for chart
        month_labels = []
        for month in all_months:
            try:
                year, month_num = month.split('-')
                month_name = calendar.month_name[int(month_num)]
                month_labels.append(f"'{month_name} {year}'")
            except:
                month_labels.append("'Unknown'")
        
        # Add chart and close HTML
        f.write(f"""
    </table>
    
    <script>
        const summaryCtx = document.getElementById('monthlySummaryChart').getContext('2d');
        const summaryChart = new Chart(summaryCtx, {{
            type: 'bar',
            data: {{
                labels: [{', '.join(month_labels)}],
                datasets: [
                    {{
                        label: 'Error Count',
                        data: [{', '.join([str(monthly_error_counts.get(month, 0)) for month in all_months])}],
                        backgroundColor: 'rgba(255, 99, 132, 0.5)',
                        borderColor: 'rgba(255, 99, 132, 1)',
                        borderWidth: 1
                    }}
                ]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        title: {{
                            display: true,
                            text: 'Number of Errors'
                        }}
                    }},
                    x: {{
                        title: {{
                            display: true,
                            text: 'Month'
                        }}
                    }}
                }},
                plugins: {{
                    title: {{
                        display: true,
                        text: 'Monthly Error Counts'
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>""")
    
    print(f"Generated monthly error summary: {monthly_report_file}")
    return monthly_report_file

def main():
    """Main function to process logs and generate reports."""
    print("Fixed Daily Error Counter")
    print("=" * 50)
    
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
        print("\n" + "=" * 50)
        project_name = project_data.get('project', '').strip().replace('.', '_')
        error_log_file = project_data.get('error_log_file', '').strip()
        
        print(f"Processing project: {project_name}")
        
        if not project_name or not error_log_file:
            print(f"Missing project name or error log file: {project_data}")
            continue
        
        processed_projects.append(project_data['project'])
        
        # Create project directory
        project_dir = os.path.join(OUTPUT_BASE_DIR, project_name)
        ensure_dir(project_dir)
        
        # Count errors by day
        daily_error_counts = count_errors_by_day(error_log_file)
        
        # Generate daily error report
        daily_report = generate_daily_error_report(project_name, daily_error_counts, project_dir)
        
        # Generate monthly error summary
        monthly_report = generate_monthly_error_summary(project_name, daily_error_counts, project_dir)
        
        # Update main index to include error reports
        index_file = os.path.join(project_dir, "index.html")
        if os.path.exists(index_file):
            # Read existing index file
            with open(index_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if error summary section already exists
            if "<h2>Error Summary Reports</h2>" not in content:
                # Add error summary section before closing </body> tag
                error_section = f"""
    <h2>Error Summary Reports</h2>
    <ul>
        <li><a href="{os.path.basename(daily_report)}">Daily Error Counts</a></li>
        <li><a href="{os.path.basename(monthly_report)}">Monthly Error Summary</a></li>
    </ul>
</body>"""
                content = content.replace("</body>", error_section)
                
                # Write updated content
                with open(index_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"Updated index file: {index_file}")
    
    print("\n" + "=" * 50)
    print("Error summary generation completed successfully.")
    print(f"Processed {len(processed_projects)} projects: {', '.join(processed_projects)}")

if __name__ == "__main__":
    main()
