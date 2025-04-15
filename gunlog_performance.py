#!/usr/bin/env python3
"""
Website Performance Analyzer

This script analyzes access logs for web projects and creates reports showing
performance metrics such as response times, status codes, and page sizes.

Usage:
    python performance_analyzer.py

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
import statistics
from collections import Counter, defaultdict

# Import configuration
try:
    from config import PROJECTS_CSV, OUTPUT_BASE_DIR, DATE_FORMAT
except ImportError:
    print("Error: config.py file not found! Please create it with the required settings.")
    exit(1)

# Regular expression for parsing access logs
# This pattern matches the common Apache/Nginx combined log format
# Example: 127.0.0.1 - - [10/Oct/2023:13:55:36 +0200] "GET /index.php HTTP/1.1" 200 2326 "http://example.com/" "Mozilla/5.0" 0.002
LOG_PATTERN = r'(.*?) - (.*?) \[(.*?)\] "(.*?)" (\d+) (\d+|-) "(.*?)" "(.*?)"(?: (\d+\.\d+))?'

# Status code categories
STATUS_CATEGORIES = {
    '2xx': list(range(200, 300)),  # Success
    '3xx': list(range(300, 400)),  # Redirection
    '4xx': list(range(400, 500)),  # Client Error
    '5xx': list(range(500, 600)),  # Server Error
}

def ensure_dir(directory):
    """Create directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)

def parse_access_log(access_log_file):
    """
    Parse access log file and extract performance metrics.
    
    Returns:
        dict: Dictionary with performance metrics
    """
    log_pattern = re.compile(LOG_PATTERN)
    metrics = {
        'requests': 0,
        'status_codes': Counter(),
        'response_times': [],
        'response_sizes': [],
        'url_metrics': defaultdict(lambda: {
            'count': 0,
            'status_codes': Counter(),
            'response_times': [],
            'response_sizes': []
        }),
        'hourly_traffic': Counter(),
        'request_methods': Counter(),
        'file_types': Counter(),
        'slow_requests': []
    }
    
    line_count = 0
    match_count = 0
    
    try:
        print(f"Opening access log file: '{access_log_file}'")
        with open(access_log_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line_count += 1
                if line_count <= 3:  # Print first few lines for debugging
                    print(f"Sample line {line_count}: {line[:100]}...")
                
                match = log_pattern.search(line)
                if match:
                    match_count += 1
                    metrics['requests'] += 1
                    
                    # Extract fields
                    ip = match.group(1)
                    date_str = match.group(3)
                    request = match.group(4)
                    status_code = int(match.group(5))
                    response_size = match.group(6)
                    referrer = match.group(7)
                    user_agent = match.group(8)
                    response_time = match.group(9)
                    
                    # Extract request method and URL
                    request_parts = request.split()
                    if len(request_parts) >= 2:
                        method = request_parts[0]
                        url = request_parts[1]
                    else:
                        method = "UNKNOWN"
                        url = "UNKNOWN"
                    
                    # Count request methods
                    metrics['request_methods'][method] += 1
                    
                    # Extract file extension
                    file_ext = os.path.splitext(url)[1].lower()
                    if file_ext:
                        metrics['file_types'][file_ext] += 1
                    
                    # Process status code
                    metrics['status_codes'][status_code] += 1
                    
                    # Process response size
                    if response_size != '-' and response_size.isdigit():
                        size = int(response_size)
                        metrics['response_sizes'].append(size)
                    
                    # Process response time if available
                    if response_time and response_time.replace('.', '', 1).isdigit():
                        time = float(response_time)
                        metrics['response_times'].append(time)
                        
                        # Track slow requests (over 1 second)
                        if time > 1.0:
                            metrics['slow_requests'].append((url, time, status_code))
                    
                    # Extract hour from timestamp for hourly traffic
                    try:
                        # Parse timestamp in format: 10/Oct/2023:13:55:36 +0200
                        timestamp_parts = date_str.split(':')
                        if len(timestamp_parts) >= 2:
                            hour = timestamp_parts[1]
                            metrics['hourly_traffic'][hour] += 1
                    except Exception:
                        pass
                    
                    # URL-specific metrics
                    url_metrics = metrics['url_metrics'][url]
                    url_metrics['count'] += 1
                    url_metrics['status_codes'][status_code] += 1
                    
                    if response_size != '-' and response_size.isdigit():
                        url_metrics['response_sizes'].append(int(response_size))
                    
                    if response_time and response_time.replace('.', '', 1).isdigit():
                        url_metrics['response_times'].append(float(response_time))
        
        print(f"Processed {line_count} lines, found {match_count} log entries")
    except Exception as e:
        print(f"Error reading log file {access_log_file}: {e}")
        return None
    
    return metrics

def calculate_summary_metrics(metrics):
    """
    Calculate summary statistics from the raw metrics.
    
    Args:
        metrics: Dictionary of raw metrics
        
    Returns:
        dict: Dictionary of summary statistics
    """
    summary = {
        'total_requests': metrics['requests'],
        'status_code_counts': dict(metrics['status_codes']),
        'status_code_percentages': {},
        'response_time_stats': {},
        'response_size_stats': {},
        'top_slowest_urls': [],
        'top_largest_urls': [],
        'hourly_traffic': dict(metrics['hourly_traffic']),
        'request_methods': dict(metrics['request_methods']),
        'file_types': dict(metrics['file_types']),
        'status_categories': {
            '2xx': 0,
            '3xx': 0,
            '4xx': 0,
            '5xx': 0,
            'other': 0
        }
    }
    
    # Calculate status code percentages
    total = metrics['requests'] or 1  # Avoid division by zero
    for status, count in metrics['status_codes'].items():
        summary['status_code_percentages'][status] = (count / total) * 100
        
        # Group by category (2xx, 3xx, etc.)
        categorized = False
        for category, range_codes in STATUS_CATEGORIES.items():
            if status in range_codes:
                summary['status_categories'][category] += count
                categorized = True
                break
        
        if not categorized:
            summary['status_categories']['other'] += count
    
    # Calculate response time statistics
    response_times = metrics['response_times']
    if response_times:
        summary['response_time_stats'] = {
            'min': min(response_times),
            'max': max(response_times),
            'avg': statistics.mean(response_times),
            'median': statistics.median(response_times),
            'p90': sorted(response_times)[int(len(response_times) * 0.9)],
            'p95': sorted(response_times)[int(len(response_times) * 0.95)],
            'p99': sorted(response_times)[int(len(response_times) * 0.99)],
        }
    
    # Calculate response size statistics
    response_sizes = metrics['response_sizes']
    if response_sizes:
        summary['response_size_stats'] = {
            'min': min(response_sizes),
            'max': max(response_sizes),
            'avg': statistics.mean(response_sizes),
            'median': statistics.median(response_sizes),
            'total_mb': sum(response_sizes) / (1024 * 1024),
        }
    
    # Get top slowest URLs
    url_response_times = []
    for url, data in metrics['url_metrics'].items():
        if data['response_times']:
            avg_time = statistics.mean(data['response_times'])
            url_response_times.append((url, avg_time, data['count']))
    
    summary['top_slowest_urls'] = sorted(url_response_times, key=lambda x: x[1], reverse=True)[:50]
    
    # Get top largest URLs by average size
    url_response_sizes = []
    for url, data in metrics['url_metrics'].items():
        if data['response_sizes']:
            avg_size = statistics.mean(data['response_sizes'])
            url_response_sizes.append((url, avg_size, data['count']))
    
    summary['top_largest_urls'] = sorted(url_response_sizes, key=lambda x: x[1], reverse=True)[:50]
    
    return summary

def generate_performance_report(project_name, metrics, summary, output_dir):
    """Generate an HTML report of performance metrics."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"performance_report_{today}.html")
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Performance Report for {project_name} - {today}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .metric-card {{ 
            border: 1px solid #ddd; 
            border-radius: 8px; 
            padding: 15px; 
            margin-bottom: 20px;
            background-color: #f9f9f9;
        }}
        .metric-title {{ 
            margin-top: 0; 
            color: #0066cc; 
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
        }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
        th, td {{ text-align: left; padding: 8px; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        tr:hover {{ background-color: #f2f2f2; }}
        .nav {{ margin-bottom: 20px; padding: 10px; background-color: #f5f5f5; }}
        .warning {{ color: #cc6600; }}
        .error {{ color: #cc0000; }}
        .success {{ color: #008800; }}
        .tabs {{ display: flex; margin-bottom: 20px; border-bottom: 1px solid #ddd; }}
        .tab {{ padding: 10px 15px; cursor: pointer; margin-right: 5px; }}
        .tab.active {{ background-color: #f0f0f0; border: 1px solid #ddd; border-bottom: none; }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}
        .chart-container {{ 
            height: 300px; 
            width: 100%; 
            margin-bottom: 20px; 
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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

    <h1>Performance Report for {project_name}</h1>
    <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="tabs">
        <div id="tab-overview" class="tab active" onclick="showTab('overview')">Overview</div>
        <div id="tab-response-times" class="tab" onclick="showTab('response-times')">Response Times</div>
        <div id="tab-status-codes" class="tab" onclick="showTab('status-codes')">Status Codes</div>
        <div id="tab-traffic" class="tab" onclick="showTab('traffic')">Traffic Analysis</div>
        <div id="tab-slow-pages" class="tab" onclick="showTab('slow-pages')">Slow Pages</div>
    </div>
    
    <div id="overview" class="tab-content active">
        <div class="metric-card">
            <h2 class="metric-title">Website Performance Summary</h2>
            <table>
                <tr>
                    <th>Total Requests</th>
                    <td>{summary['total_requests']}</td>
                </tr>
"""
    
    # Add response time overview
    if summary.get('response_time_stats'):
        rt_stats = summary['response_time_stats']
        html_content += f"""
                <tr>
                    <th>Average Response Time</th>
                    <td>{rt_stats.get('avg', 0):.3f} seconds</td>
                </tr>
                <tr>
                    <th>Median Response Time</th>
                    <td>{rt_stats.get('median', 0):.3f} seconds</td>
                </tr>
                <tr>
                    <th>95th Percentile Response Time</th>
                    <td>{rt_stats.get('p95', 0):.3f} seconds</td>
                </tr>
                <tr>
                    <th>Max Response Time</th>
                    <td class="{('warning' if rt_stats.get('max', 0) > 3 else 'success')}">{rt_stats.get('max', 0):.3f} seconds</td>
                </tr>
"""
    
    # Add status code overview
    status_categories = summary.get('status_categories', {})
    success_rate = status_categories.get('2xx', 0) / summary['total_requests'] * 100 if summary['total_requests'] else 0
    error_rate = (status_categories.get('4xx', 0) + status_categories.get('5xx', 0)) / summary['total_requests'] * 100 if summary['total_requests'] else 0
    
    html_content += f"""
                <tr>
                    <th>Success Rate (2xx)</th>
                    <td class="{('success' if success_rate > 95 else 'warning' if success_rate > 90 else 'error')}">{success_rate:.1f}%</td>
                </tr>
                <tr>
                    <th>Error Rate (4xx/5xx)</th>
                    <td class="{('success' if error_rate < 1 else 'warning' if error_rate < 5 else 'error')}">{error_rate:.1f}%</td>
                </tr>
"""
    
    # Add bandwidth overview
    if summary.get('response_size_stats'):
        size_stats = summary['response_size_stats']
        html_content += f"""
                <tr>
                    <th>Total Bandwidth</th>
                    <td>{size_stats.get('total_mb', 0):.2f} MB</td>
                </tr>
                <tr>
                    <th>Average Response Size</th>
                    <td>{size_stats.get('avg', 0):.0f} bytes</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Status Code Distribution</h2>
            <div class="chart-container">
                <canvas id="status-chart"></canvas>
            </div>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Hourly Traffic</h2>
            <div class="chart-container">
                <canvas id="traffic-chart"></canvas>
            </div>
        </div>
    </div>
    
    <div id="response-times" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Response Time Statistics</h2>
"""
    
    if summary.get('response_time_stats'):
        rt_stats = summary['response_time_stats']
        html_content += f"""
            <table>
                <tr>
                    <th>Minimum</th>
                    <td>{rt_stats.get('min', 0):.3f} seconds</td>
                </tr>
                <tr>
                    <th>Maximum</th>
                    <td>{rt_stats.get('max', 0):.3f} seconds</td>
                </tr>
                <tr>
                    <th>Average</th>
                    <td>{rt_stats.get('avg', 0):.3f} seconds</td>
                </tr>
                <tr>
                    <th>Median (50th Percentile)</th>
                    <td>{rt_stats.get('median', 0):.3f} seconds</td>
                </tr>
                <tr>
                    <th>90th Percentile</th>
                    <td>{rt_stats.get('p90', 0):.3f} seconds</td>
                </tr>
                <tr>
                    <th>95th Percentile</th>
                    <td>{rt_stats.get('p95', 0):.3f} seconds</td>
                </tr>
                <tr>
                    <th>99th Percentile</th>
                    <td>{rt_stats.get('p99', 0):.3f} seconds</td>
                </tr>
            </table>
"""
    else:
        html_content += """
            <p>No response time data available. The log may not include response time information.</p>
"""
    
    html_content += """
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Top 20 Slowest URLs (By Average Response Time)</h2>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Avg Response Time</th>
                    <th>Request Count</th>
                </tr>
"""
    
    # Add slowest URLs
    for url, avg_time, count in summary.get('top_slowest_urls', [])[:20]:
        time_class = 'success' if avg_time < 0.5 else 'warning' if avg_time < 1.0 else 'error'
        html_content += f"""
                <tr>
                    <td>{url}</td>
                    <td class="{time_class}">{avg_time:.3f} seconds</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
    </div>
    
    <div id="status-codes" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Status Code Details</h2>
            <table>
                <tr>
                    <th>Status Code</th>
                    <th>Count</th>
                    <th>Percentage</th>
                    <th>Description</th>
                </tr>
"""
    
    # Status code descriptions
    status_descriptions = {
        200: "OK",
        201: "Created",
        204: "No Content",
        206: "Partial Content",
        301: "Moved Permanently",
        302: "Found (Temporary Redirect)",
        304: "Not Modified",
        307: "Temporary Redirect",
        308: "Permanent Redirect",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        408: "Request Timeout",
        410: "Gone",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout"
    }
    
    # Add status code rows
    status_codes = sorted(summary['status_code_counts'].items())
    for status, count in status_codes:
        percentage = summary['status_code_percentages'].get(status, 0)
        description = status_descriptions.get(status, "Unknown")
        
        # Determine CSS class based on status code
        if 200 <= status < 300:
            status_class = "success"
        elif 300 <= status < 400:
            status_class = "warning"
        else:
            status_class = "error"
        
        html_content += f"""
                <tr>
                    <td class="{status_class}">{status}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                    <td>{description}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Request Methods</h2>
            <table>
                <tr>
                    <th>Method</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
"""
    
    # Add request method rows
    total_requests = summary['total_requests'] or 1  # Avoid division by zero
    for method, count in sorted(summary['request_methods'].items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_requests) * 100
        html_content += f"""
                <tr>
                    <td>{method}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
    </div>
    
    <div id="traffic" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Response Size Statistics</h2>
"""
    
    if summary.get('response_size_stats'):
        size_stats = summary['response_size_stats']
        html_content += f"""
            <table>
                <tr>
                    <th>Minimum Size</th>
                    <td>{size_stats.get('min', 0):,} bytes</td>
                </tr>
                <tr>
                    <th>Maximum Size</th>
                    <td>{size_stats.get('max', 0):,} bytes</td>
                </tr>
                <tr>
                    <th>Average Size</th>
                    <td>{size_stats.get('avg', 0):.0f} bytes</td>
                </tr>
                <tr>
                    <th>Median Size</th>
                    <td>{size_stats.get('median', 0):.0f} bytes</td>
                </tr>
                <tr>
                    <th>Total Bandwidth</th>
                    <td>{size_stats.get('total_mb', 0):.2f} MB</td>
                </tr>
            </table>
"""
    else:
        html_content += """
            <p>No response size data available. The log may not include response size information.</p>
"""
    
    html_content += """
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Top 20 Largest URLs (By Average Size)</h2>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Avg Size</th>
                    <th>Request Count</th>
                </tr>
"""
    
    # Add largest URLs
    for url, avg_size, count in summary.get('top_largest_urls', [])[:20]:
        html_content += f"""
                <tr>
                    <td>{url}</td>
                    <td>{avg_size:,.0f} bytes</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">File Type Distribution</h2>
            <table>
                <tr>
                    <th>File Type</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
"""
    
    # Add file type rows
    for file_type, count in sorted(summary['file_types'].items(), key=lambda x: x[1], reverse=True)[:20]:
        percentage = (count / total_requests) * 100
        html_content += f"""
                <tr>
                    <td>{file_type or '(no extension)'}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
    </div>
    
    <div id="slow-pages" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Individual Slow Requests (> 1 second)</h2>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Response Time</th>
                    <th>Status Code</th>
                </tr>
"""
    
    # Add individual slow requests
    for url, time, status in sorted(metrics['slow_requests'], key=lambda x: x[1], reverse=True)[:100]:
        time_class = 'warning' if time < 3.0 else 'error'
        html_content += f"""
                <tr>
                    <td>{url}</td>
                    <td class="{time_class}">{time:.3f} seconds</td>
                    <td>{status}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
    </div>
    
    <script>
        // Status code chart
        const statusCtx = document.getElementById('status-chart').getContext('2d');
        const statusChart = new Chart(statusCtx, {
            type: 'pie',
            data: {
                labels: [
"""
    
    # Add status category labels
    for category in summary['status_categories'].keys():
        html_content += f"                    '{category}',\n"
    
    html_content += """
                ],
                datasets: [{
                    data: [
"""
    
    # Add status category values
    for count in summary['status_categories'].values():
        html_content += f"                        {count},\n"
    
    html_content += """
                    ],
                    backgroundColor: [
                        '#4caf50',  /* 2xx - Success */
                        '#ff9800',  /* 3xx - Redirect */
                        '#f44336',  /* 4xx - Client Error */
                        '#9c27b0',  /* 5xx - Server Error */
                        '#607d8b'   /* Other */
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    title: {
                        display: true,
                        text: 'HTTP Status Code Distribution'
                    }
                }
            }
        });
        
        // Traffic chart
        const trafficCtx = document.getElementById('traffic-chart').getContext('2d');
        const trafficChart = new Chart(trafficCtx, {
            type: 'bar',
            data: {
                labels: [
"""
    
    # Add hour labels
    for hour in range(24):
        html_content += f"                    '{hour:02d}',\n"
    
    html_content += """
                ],
                datasets: [{
                    label: 'Requests per Hour',
                    data: [
"""
    
    # Add hourly traffic data
    for hour in range(24):
        hour_str = f"{hour:02d}"
        count = summary['hourly_traffic'].get(hour_str, 0)
        html_content += f"                        {count},\n"
    
    html_content += """
                    ],
                    backgroundColor: '#2196f3',
                    borderColor: '#1976d2',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of Requests'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Hour of Day'
                        }
                    }
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Hourly Traffic Distribution'
                    }
                }
            }
        });
    </script>
</body>
</html>
"""
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return report_file

def generate_plain_text_report(project_name, metrics, summary, output_dir):
    """Generate a plain text report of performance metrics."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"performance_report_{today}.txt")
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f"Performance Report for {project_name}\n")
        f.write("="*50 + "\n")
        f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Overview
        f.write("PERFORMANCE OVERVIEW\n")
        f.write("-"*50 + "\n")
        f.write(f"Total Requests: {summary['total_requests']}\n")
        
        # Response time stats
        if summary.get('response_time_stats'):
            rt_stats = summary['response_time_stats']
            f.write(f"Average Response Time: {rt_stats.get('avg', 0):.3f} seconds\n")
            f.write(f"Median Response Time: {rt_stats.get('median', 0):.3f} seconds\n")
            f.write(f"95th Percentile Response Time: {rt_stats.get('p95', 0):.3f} seconds\n")
            f.write(f"Maximum Response Time: {rt_stats.get('max', 0):.3f} seconds\n")
        
        # Status code stats
        status_categories = summary.get('status_categories', {})
        success_rate = status_categories.get('2xx', 0) / summary['total_requests'] * 100 if summary['total_requests'] else 0
        error_rate = (status_categories.get('4xx', 0) + status_categories.get('5xx', 0)) / summary['total_requests'] * 100 if summary['total_requests'] else 0
        
        f.write(f"Success Rate (2xx): {success_rate:.1f}%\n")
        f.write(f"Error Rate (4xx/5xx): {error_rate:.1f}%\n")
        
        # Bandwidth stats
        if summary.get('response_size_stats'):
            size_stats = summary['response_size_stats']
            f.write(f"Total Bandwidth: {size_stats.get('total_mb', 0):.2f} MB\n")
            f.write(f"Average Response Size: {size_stats.get('avg', 0):.0f} bytes\n\n")
        
        # Status code breakdown
        f.write("STATUS CODE BREAKDOWN\n")
        f.write("-"*50 + "\n")
        for status, count in sorted(summary['status_code_counts'].items()):
            percentage = summary['status_code_percentages'].get(status, 0)
            f.write(f"HTTP {status}: {count} requests ({percentage:.1f}%)\n")
        f.write("\n")
        
        # Slow URLs
        f.write("TOP 20 SLOWEST URLS\n")
        f.write("-"*50 + "\n")
        for i, (url, avg_time, count) in enumerate(summary.get('top_slowest_urls', [])[:20], 1):
            f.write(f"{i}. {url} - {avg_time:.3f} seconds (requests: {count})\n")
        f.write("\n")
        
        # Hourly traffic
        f.write("HOURLY TRAFFIC\n")
        f.write("-"*50 + "\n")
        for hour in range(24):
            hour_str = f"{hour:02d}"
            count = summary['hourly_traffic'].get(hour_str, 0)
            f.write(f"Hour {hour_str}: {count} requests\n")
    
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
        metrics = parse_access_log(access_log_file)
        
        if not metrics:
            print(f"No metrics found or couldn't parse log for {project_name}")
            continue
        
        # Calculate summary statistics
        summary = calculate_summary_metrics(metrics)
        
        # Generate HTML report
        html_report_file = generate_performance_report(project_name, metrics, summary, date_dir)
        print(f"Generated HTML performance report for {project_name}: {html_report_file}")
        
        # Generate plain text report
        text_report_file = generate_plain_text_report(project_name, metrics, summary, date_dir)
        print(f"Generated text performance report for {project_name}: {text_report_file}")
        
        # Create copies in the project directory for the summary
        html_report_basename = os.path.basename(html_report_file)
        text_report_basename = os.path.basename(text_report_file)
        shutil.copy(html_report_file, os.path.join(project_dir, html_report_basename))
        shutil.copy(text_report_file, os.path.join(project_dir, text_report_basename))
    
    print("Performance analysis completed successfully.")

if __name__ == "__main__":
    main()
