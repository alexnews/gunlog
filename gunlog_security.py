#!/usr/bin/env python3
"""
Simplified Website Security Analyzer

This script analyzes access logs for web projects and creates reports showing
security-related events, potential threats, and suspicious activities.

Usage:
    python security_analyzer.py

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

# Regular expression for parsing access logs
# This pattern matches the common Apache/Nginx combined log format
LOG_PATTERN = r'(.*?) - (.*?) \[(.*?)\] "(.*?)" (\d+) (\d+|-) "(.*?)" "(.*?)"'

# Patterns for identifying security threats (simplified)
THREAT_PATTERNS = {
    'SQL Injection': [
        r'(?i)union\s+select',
        r'(?i)select.+from',
        r'(?i)1=1',
        r'(?i)or\s+1\s*=',
        r'(?i)drop\s+table',
    ],
    'XSS Attack': [
        r'(?i)<script',
        r'(?i)javascript:',
        r'(?i)onerror=',
        r'(?i)onload=',
        r'(?i)onclick=',
    ],
    'Path Traversal': [
        r'(?i)\.\./',
        r'(?i)\.\.%2f',
        r'(?i)/etc/passwd',
    ],
    'Command Injection': [
        r'(?i);\s*[a-z]+',
        r'(?i)\|\s*[a-z]+',
    ],
    'Server Scan': [
        r'(?i)/admin',
        r'(?i)/wp-admin',
        r'(?i)/phpmyadmin',
        r'(?i)/.git',
        r'(?i)/.env',
    ],
    'Suspicious User Agent': [
        r'(?i)sqlmap',
        r'(?i)nikto',
        r'(?i)nmap',
        r'(?i)gobuster',
        r'(?i)dirbuster',
    ],
}

# Security-related status codes
SECURITY_STATUS_CODES = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    405: 'Method Not Allowed',
    406: 'Not Acceptable',
    429: 'Too Many Requests',
}

def ensure_dir(directory):
    """Create directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)

def parse_time(time_str):
    """
    Parse time string from access log.
    
    Args:
        time_str: Time string in format like "10/Oct/2023:13:55:36 +0200"
        
    Returns:
        tuple: (datetime object, hour, day_of_week)
    """
    try:
        # Extract parts: 10/Oct/2023:13:55:36 +0200
        date_part, time_part = time_str.split(':', 1)
        day, month, year = date_part.split('/')
        hour, minute, rest = time_part.split(':', 2)
        second = rest.split()[0]
        
        # Convert month name to number
        month_names = {
            'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
            'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
        }
        month_num = month_names.get(month, 1)
        
        # Create datetime object
        dt = datetime.datetime(int(year), month_num, int(day), int(hour), int(minute), int(second))
        
        return dt, int(hour), dt.weekday()
    except:
        # Return default values if parsing fails
        now = datetime.datetime.now()
        return now, 0, 0

def detect_threats(request, user_agent, referrer):
    """
    Detect potential security threats.
    
    Args:
        request: HTTP request string
        user_agent: User agent string
        referrer: Referrer string
        
    Returns:
        list: List of detected threat types
    """
    detected_threats = []
    
    # Combine request, user agent, and referrer for threat detection
    targets = [
        request,
        user_agent,
        referrer if referrer != '-' else '',
    ]
    
    # Check each target string against each threat pattern
    for threat_type, patterns in THREAT_PATTERNS.items():
        for pattern in patterns:
            for target in targets:
                if re.search(pattern, target):
                    detected_threats.append(threat_type)
                    break
            if threat_type in detected_threats:
                break
    
    return detected_threats

def is_private_ip(ip):
    """
    Simple check if an IP is private/internal.
    """
    private_prefixes = [
        '10.',
        '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.',
        '172.24.', '172.25.', '172.26.', '172.27.',
        '172.28.', '172.29.', '172.30.', '172.31.',
        '192.168.',
        '127.',
        'localhost',
    ]
    return any(ip.startswith(prefix) for prefix in private_prefixes)

def parse_access_log(access_log_file):
    """
    Parse access log file and extract security metrics.
    
    Returns:
        dict: Dictionary with security metrics
    """
    log_pattern = re.compile(LOG_PATTERN)
    
    # Initialize metrics
    metrics = {
        'total_requests': 0,
        'security_events': [],
        'suspicious_ips': defaultdict(list),
        'attack_types': Counter(),
        'status_codes': Counter(),
        'security_status_codes': Counter(),
        'attack_vectors': defaultdict(Counter),
        'high_frequency_ips': Counter(),
        'suspicious_user_agents': Counter(),
        'http_methods': Counter(),
        'sensitive_urls_accessed': Counter(),
        'hourly_attacks': defaultdict(Counter),
        'top_attack_sources': Counter(),
        'attack_time_distribution': defaultdict(int),
        'firewall_recommendations': set(),
        'suspicious_requests': [],
    }
    
    # Sensitive resources to monitor
    sensitive_resources = [
        '/admin', '/wp-admin', '/login', '/wp-login', '/administrator', 
        '/phpmyadmin', '/myadmin', '/.git', '/.env', '/config', 
        '/wp-config', '/backup', '/db', '/database',
    ]
    
    # Track request frequency by IP
    ip_request_times = defaultdict(list)
    ip_auth_failures = defaultdict(int)
    
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
                    metrics['total_requests'] += 1
                    
                    # Extract fields
                    ip = match.group(1)
                    auth = match.group(2)
                    time_str = match.group(3)
                    request = match.group(4)
                    status_code = int(match.group(5))
                    response_size = match.group(6)
                    referrer = match.group(7)
                    user_agent = match.group(8)
                    
                    # Skip internal IPs
                    if is_private_ip(ip):
                        continue
                    
                    # Parse timestamp
                    timestamp, hour, day_of_week = parse_time(time_str)
                    
                    # Track HTTP methods
                    method = ''
                    if ' ' in request:
                        method = request.split(' ')[0]
                        metrics['http_methods'][method] += 1
                    
                    # Extract URL
                    url = ''
                    if ' ' in request and len(request.split(' ')) > 1:
                        url = request.split(' ')[1]
                    
                    # Track status codes
                    metrics['status_codes'][status_code] += 1
                    if status_code in SECURITY_STATUS_CODES:
                        metrics['security_status_codes'][status_code] += 1
                    
                    # Check for authentication failures (401, 403)
                    if status_code in [401, 403]:
                        ip_auth_failures[ip] += 1
                        
                        # Record security event for auth failures
                        if ip_auth_failures[ip] >= 3:
                            event = {
                                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                                'ip': ip,
                                'event_type': 'Authentication Failure',
                                'details': f"Multiple auth failures ({ip_auth_failures[ip]} attempts)",
                                'url': url,
                                'user_agent': user_agent,
                                'status_code': status_code,
                            }
                            metrics['security_events'].append(event)
                            metrics['firewall_recommendations'].add(f"Block IP {ip} - Multiple auth failures")
                    
                    # Record requests to sensitive resources
                    for resource in sensitive_resources:
                        if resource in url:
                            metrics['sensitive_urls_accessed'][url] += 1
                            
                            # Record security event for sensitive resource access
                            event = {
                                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                                'ip': ip,
                                'event_type': 'Sensitive Resource Access',
                                'details': f"Access to {resource}",
                                'url': url,
                                'user_agent': user_agent,
                                'status_code': status_code,
                            }
                            metrics['security_events'].append(event)
                    
                    # Check for rate limiting issues
                    ip_request_times[ip].append(timestamp)
                    
                    # Keep only the last 100 timestamps per IP
                    if len(ip_request_times[ip]) > 100:
                        ip_request_times[ip] = ip_request_times[ip][-100:]
                    
                    # Check if this IP has made too many requests recently
                    recent_requests = [t for t in ip_request_times[ip] 
                                      if (timestamp - t).total_seconds() < 60]
                    
                    if len(recent_requests) > 60:
                        metrics['high_frequency_ips'][ip] += 1
                        
                        # Only record rate limiting event once per IP
                        if metrics['high_frequency_ips'][ip] == 1:
                            event = {
                                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                                'ip': ip,
                                'event_type': 'Rate Limit Exceeded',
                                'details': f"{len(recent_requests)} requests in <60 seconds",
                                'url': url,
                                'user_agent': user_agent,
                                'status_code': status_code,
                            }
                            metrics['security_events'].append(event)
                            metrics['firewall_recommendations'].add(f"Rate limit IP {ip}")
                    
                    # Detect threats in request
                    threats = detect_threats(request, user_agent, referrer)
                    
                    if threats:
                        for threat in threats:
                            metrics['attack_types'][threat] += 1
                            metrics['attack_vectors'][threat][url] += 1
                            metrics['top_attack_sources'][ip] += 1
                            metrics['hourly_attacks'][hour][threat] += 1
                            metrics['attack_time_distribution'][hour] += 1
                        
                        metrics['suspicious_ips'][ip].append({
                            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                            'request': request,
                            'threat_types': threats,
                            'status_code': status_code,
                            'user_agent': user_agent,
                            'referrer': referrer
                        })
                        
                        metrics['suspicious_user_agents'][user_agent] += 1
                        
                        # Record security event for attack
                        event = {
                            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                            'ip': ip,
                            'event_type': 'Attack Detected',
                            'details': ', '.join(threats),
                            'url': url,
                            'user_agent': user_agent,
                            'status_code': status_code,
                            'request': request[:100] if len(request) > 100 else request,
                        }
                        metrics['security_events'].append(event)
                        
                        # Generate firewall recommendations based on threats
                        if 'SQL Injection' in threats or 'XSS Attack' in threats:
                            metrics['firewall_recommendations'].add(f"Block IP {ip} - Attack attempts")
                        
                        # Store suspicious request for further analysis
                        if len(metrics['suspicious_requests']) < 100:  # Limit stored requests
                            metrics['suspicious_requests'].append({
                                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                                'ip': ip,
                                'request': request,
                                'threat_types': threats,
                                'status_code': status_code,
                                'user_agent': user_agent,
                                'referrer': referrer
                            })
        
        print(f"Processed {line_count} lines, matched {match_count} entries")
    except Exception as e:
        print(f"Error reading log file {access_log_file}: {e}")
        return None
    
    return metrics

def generate_security_report(project_name, metrics, output_dir):
    """Generate an HTML report of security metrics."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"security_report_{today}.html")
    
    # Calculate security score based on metrics
    attack_count = sum(metrics['attack_types'].values())
    auth_failures = sum(1 for event in metrics['security_events'] if event['event_type'] == 'Authentication Failure')
    sensitive_access = sum(metrics['sensitive_urls_accessed'].values())
    
    security_score = 100
    if attack_count > 0:
        security_score -= min(50, attack_count)
    if auth_failures > 0:
        security_score -= min(20, auth_failures * 5)
    if sensitive_access > 0:
        security_score -= min(20, sensitive_access * 2)
    
    security_score = max(0, security_score)  # Ensure score doesn't go negative
    
    # Determine security status based on score
    if security_score >= 90:
        security_status = 'Good'
        status_color = '#4caf50'
    elif security_score >= 70:
        security_status = 'Fair'
        status_color = '#ff9800'
    elif security_score >= 50:
        security_status = 'Poor'
        status_color = '#f44336'
    else:
        security_status = 'Critical'
        status_color = '#d32f2f'
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Report for {project_name} - {today}</title>
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
        .tabs {{ display: flex; margin-bottom: 20px; border-bottom: 1px solid #ddd; }}
        .tab {{ padding: 10px 15px; cursor: pointer; margin-right: 5px; }}
        .tab.active {{ background-color: #f0f0f0; border: 1px solid #ddd; border-bottom: none; }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f44336; }}
        .medium {{ color: #ff9800; }}
        .low {{ color: #4caf50; }}
        .alert-box {{
            border-left: 4px solid #ff9800;
            background-color: #fff3e0;
            padding: 10px;
            margin-bottom: 10px;
        }}
        .rec-box {{
            border-left: 4px solid #4caf50;
            background-color: #e8f5e9;
            padding: 10px;
            margin-bottom: 10px;
        }}
        .event-box {{
            border: 1px solid #ddd;
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 4px;
        }}
        .event-time {{
            color: #666;
            font-size: 0.9em;
        }}
        .event-type {{
            font-weight: bold;
            color: #d32f2f;
        }}
        .event-details {{
            margin-top: 5px;
        }}
        pre {{
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 0.9em;
        }}
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

    <h1>Security Report for {project_name}</h1>
    <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="tabs">
        <div id="tab-overview" class="tab active" onclick="showTab('overview')">Overview</div>
        <div id="tab-events" class="tab" onclick="showTab('events')">Security Events</div>
        <div id="tab-threats" class="tab" onclick="showTab('threats')">Threat Details</div>
        <div id="tab-recommendations" class="tab" onclick="showTab('recommendations')">Recommendations</div>
    </div>
    
    <div id="overview" class="tab-content active">
        <div class="metric-card">
            <h2 class="metric-title">Security Status</h2>
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h3 style="margin-top: 0;">Security Score</h3>
                    <div style="font-size: 48px; font-weight: bold; color: {status_color};">{security_score}</div>
                    <p>Status: <span style="font-weight: bold; color: {status_color};">{security_status}</span></p>
                </div>
            </div>
            
            <div style="margin-top: 20px;">
                <h3>Security Summary</h3>
                <table>
                    <tr>
                        <th>Metric</th>
                        <th>Value</th>
                    </tr>
                    <tr>
                        <td>Total Requests Analyzed</td>
                        <td>{metrics['total_requests']}</td>
                    </tr>
                    <tr>
                        <td>Attack Attempts Detected</td>
                        <td>{attack_count}</td>
                    </tr>
                    <tr>
                        <td>Suspicious IPs</td>
                        <td>{len(metrics['suspicious_ips'])}</td>
                    </tr>
                    <tr>
                        <td>Authentication Failures</td>
                        <td>{auth_failures}</td>
                    </tr>
                    <tr>
                        <td>Sensitive Resource Access Attempts</td>
                        <td>{sensitive_access}</td>
                    </tr>
                    <tr>
                        <td>Rate Limit Violations</td>
                        <td>{len(metrics['high_frequency_ips'])}</td>
                    </tr>
                </table>
            </div>
"""
    
    # Add alert boxes for critical issues
    if attack_count > 0 or auth_failures > 5 or security_score < 70:
        html_content += """
            <div style="margin-top: 20px;">
                <h3>Critical Alerts</h3>
"""
        
        if attack_count > 0:
            html_content += f"""
                <div class="alert-box">
                    <strong>Attack attempts detected!</strong> {attack_count} potential attack attempts were identified.
                    Most common attack type: {metrics['attack_types'].most_common(1)[0][0] if metrics['attack_types'] else 'N/A'}
                </div>
"""
        
        if auth_failures > 5:
            html_content += f"""
                <div class="alert-box">
                    <strong>Brute force attempt suspected!</strong> {auth_failures} authentication failures detected.
                </div>
"""
        
        if len(metrics['high_frequency_ips']) > 0:
            html_content += f"""
                <div class="alert-box">
                    <strong>Rate limiting violations!</strong> {len(metrics['high_frequency_ips'])} IPs exceeded request rate limits.
                </div>
"""
        
        html_content += """
            </div>
"""
    
    html_content += """
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Attack Types</h2>
            <table>
                <tr>
                    <th>Attack Type</th>
                    <th>Count</th>
                </tr>
"""
    
    # Add attack type rows
    for attack_type, count in metrics['attack_types'].most_common():
        html_content += f"""
                <tr>
                    <td>{attack_type}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Security Status Codes</h2>
            <table>
                <tr>
                    <th>Status Code</th>
                    <th>Description</th>
                    <th>Count</th>
                </tr>
"""
    
    # Add security status code rows
    for status_code, count in sorted(metrics['security_status_codes'].items()):
        description = SECURITY_STATUS_CODES.get(status_code, 'Unknown')
        html_content += f"""
                <tr>
                    <td>{status_code}</td>
                    <td>{description}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
    </div>
    
    <div id="events" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Security Event Timeline</h2>
            <p>Chronological list of security events detected in logs.</p>
"""
    
    # Add security events
    for event in sorted(metrics['security_events'], key=lambda x: x['timestamp'], reverse=True)[:50]:
        # Determine severity class based on event type
        severity_class = 'medium'
        if event['event_type'] == 'Attack Detected':
            severity_class = 'high'
        elif event['event_type'] == 'Authentication Failure':
            severity_class = 'high' if 'Multiple auth failures' in event['details'] else 'medium'
        elif event['event_type'] == 'Rate Limit Exceeded':
            severity_class = 'medium'
        elif event['event_type'] == 'Sensitive Resource Access':
            severity_class = 'low'
        
        html_content += f"""
            <div class="event-box">
                <div><span class="event-time">{event['timestamp']}</span> - <span class="event-type {severity_class}">{event['event_type']}</span></div>
                <div class="event-details">
                    <strong>IP:</strong> {event['ip']} | <strong>Status:</strong> {event.get('status_code', 'N/A')}<br>
                    <strong>Details:</strong> {event['details']}<br>
                    <strong>URL:</strong> {event.get('url', 'N/A')}
                </div>
            </div>
"""
    
    html_content += """
        </div>
    </div>
    
    <div id="threats" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Top Attack Sources</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Attack Count</th>
                    <th>Attack Types</th>
                </tr>
"""
    
    # Add attack source rows
    for ip, count in metrics['top_attack_sources'].most_common(20):
        # Collect unique attack types for this IP
        attack_types = set()
        for event in metrics['suspicious_ips'].get(ip, []):
            for threat in event.get('threat_types', []):
                attack_types.add(threat)
        
        attack_types_str = ', '.join(attack_types) if attack_types else 'Unknown'
        
        html_content += f"""
                <tr>
                    <td>{ip}</td>
                    <td>{count}</td>
                    <td>{attack_types_str}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Suspicious Requests</h2>
            <p>Sample of suspicious requests detected in the logs.</p>
"""
    
    # Add suspicious requests
    for i, req in enumerate(metrics['suspicious_requests'][:20]):
        html_content += f"""
            <div class="event-box">
                <div><span class="event-time">{req['timestamp']}</span> - <span class="event-type">{', '.join(req['threat_types'])}</span></div>
                <div class="event-details">
                    <strong>IP:</strong> {req['ip']} | <strong>Status:</strong> {req['status_code']}<br>
                    <strong>Request:</strong> <pre>{req['request']}</pre>
                    <strong>User Agent:</strong> {req['user_agent']}<br>
                    <strong>Referrer:</strong> {req['referrer'] if req['referrer'] != '-' else 'None'}
                </div>
            </div>
"""
    
    html_content += """
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Sensitive Resource Access</h2>
            <p>Attempts to access sensitive resources on your site.</p>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Access Attempts</th>
                </tr>
"""
    
    # Add sensitive URL access rows
    for url, count in metrics['sensitive_urls_accessed'].most_common():
        html_content += f"""
                <tr>
                    <td>{url}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
    </div>
    
    <div id="recommendations" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Security Recommendations</h2>
            <p>Based on the analysis, here are recommended actions to improve security:</p>
"""
    
    # Add firewall recommendations
    if metrics['firewall_recommendations']:
        html_content += """
            <h3>Firewall Rules</h3>
"""
        
        for rec in sorted(metrics['firewall_recommendations']):
            html_content += f"""
            <div class="rec-box">
                {rec}
            </div>
"""
    
    # Add general recommendations based on detected issues
    html_content += """
            <h3>General Recommendations</h3>
"""
    
    if any('SQL Injection' in attack for attack in metrics['attack_types']):
        html_content += """
            <div class="rec-box">
                <strong>Implement input validation and prepared statements</strong> - SQL injection attempts were detected. 
                Ensure all database queries use parameterized statements and validate all user input.
            </div>
"""
    
    if any('XSS Attack' in attack for attack in metrics['attack_types']):
        html_content += """
            <div class="rec-box">
                <strong>Implement Content Security Policy (CSP)</strong> - Cross-site scripting (XSS) attempts were detected. 
                Implement CSP headers and sanitize all user input before rendering it on pages.
            </div>
"""
    
    if any('Path Traversal' in attack for attack in metrics['attack_types']):
        html_content += """
            <div class="rec-box">
                <strong>Secure file operations</strong> - Path traversal attempts were detected. 
                Validate file paths and implement proper access controls for file operations.
            </div>
"""
    
    if len(metrics['high_frequency_ips']) > 0:
        html_content += """
            <div class="rec-box">
                <strong>Implement rate limiting</strong> - Suspicious high-frequency requests were detected. 
                Implement rate limiting to prevent DDoS attacks and brute force attempts.
            </div>
"""
    
    if sum(1 for event in metrics['security_events'] if event['event_type'] == 'Authentication Failure') > 0:
        html_content += """
            <div class="rec-box">
                <strong>Enhance authentication security</strong> - Multiple authentication failures were detected. 
                Implement account lockouts, stronger password policies, and consider multi-factor authentication.
            </div>
"""
    
    # Add common security best practices
    html_content += """
            <div class="rec-box">
                <strong>Keep software updated</strong> - Regularly update your CMS, plugins, and all server software to patch vulnerabilities.
            </div>
            
            <div class="rec-box">
                <strong>Implement a Web Application Firewall (WAF)</strong> - A WAF can block many common attack vectors automatically.
            </div>
            
            <div class="rec-box">
                <strong>Regular security assessments</strong> - Schedule regular security audits and penetration testing to identify vulnerabilities.
            </div>
        </div>
    </div>
    
    <script>
        // Show the overview tab by default
        showTab('overview');
    </script>
</body>
</html>
"""
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return report_file

def generate_plain_text_report(project_name, metrics, output_dir):
    """Generate a plain text report of security metrics."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"security_report_{today}.txt")
    
    # Calculate security score
    attack_count = sum(metrics['attack_types'].values())
    auth_failures = sum(1 for event in metrics['security_events'] if event['event_type'] == 'Authentication Failure')
    sensitive_access = sum(metrics['sensitive_urls_accessed'].values())
    
    security_score = 100
    if attack_count > 0:
        security_score -= min(50, attack_count)
    if auth_failures > 0:
        security_score -= min(20, auth_failures * 5)
    if sensitive_access > 0:
        security_score -= min(20, sensitive_access * 2)
    
    security_score = max(0, security_score)  # Ensure score doesn't go negative
    
    # Determine security status based on score
    if security_score >= 90:
        security_status = 'Good'
    elif security_score >= 70:
        security_status = 'Fair'
    elif security_score >= 50:
        security_status = 'Poor'
    else:
        security_status = 'Critical'
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f"Security Report for {project_name}\n")
        f.write("="*50 + "\n")
        f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Security overview
        f.write("SECURITY OVERVIEW\n")
        f.write("-"*50 + "\n")
        f.write(f"Security Score: {security_score}/100 ({security_status})\n")
        f.write(f"Total Requests Analyzed: {metrics['total_requests']}\n")
        f.write(f"Attack Attempts Detected: {attack_count}\n")
        f.write(f"Suspicious IPs: {len(metrics['suspicious_ips'])}\n")
        f.write(f"Authentication Failures: {auth_failures}\n")
        f.write(f"Sensitive Resource Access Attempts: {sensitive_access}\n")
        f.write(f"Rate Limit Violations: {len(metrics['high_frequency_ips'])}\n\n")
        
        # Attack types
        f.write("ATTACK TYPES\n")
        f.write("-"*50 + "\n")
        for attack_type, count in metrics['attack_types'].most_common():
            f.write(f"{attack_type}: {count}\n")
        f.write("\n")
        
        # Top attack sources
        f.write("TOP 10 ATTACK SOURCES\n")
        f.write("-"*50 + "\n")
        for i, (ip, count) in enumerate(metrics['top_attack_sources'].most_common(10), 1):
            f.write(f"{i}. IP: {ip} - {count} attacks\n")
        f.write("\n")
        
        # Security events summary
        f.write("RECENT SECURITY EVENTS\n")
        f.write("-"*50 + "\n")
        for i, event in enumerate(sorted(metrics['security_events'], key=lambda x: x['timestamp'], reverse=True)[:20], 1):
            f.write(f"{i}. [{event['timestamp']}] {event['event_type']}: {event['details']}\n")
            f.write(f"   IP: {event['ip']} | URL: {event.get('url', 'N/A')}\n\n")
        
        # Security recommendations
        f.write("SECURITY RECOMMENDATIONS\n")
        f.write("-"*50 + "\n")
        
        # Add firewall recommendations
        if metrics['firewall_recommendations']:
            f.write("Firewall Rules:\n")
            for rec in sorted(metrics['firewall_recommendations']):
                f.write(f"- {rec}\n")
            f.write("\n")
        
        # General recommendations
        f.write("General Recommendations:\n")
        
        if any('SQL Injection' in attack for attack in metrics['attack_types']):
            f.write("- Implement input validation and prepared statements for all database queries\n")
        
        if any('XSS Attack' in attack for attack in metrics['attack_types']):
            f.write("- Implement Content Security Policy (CSP) and sanitize user input\n")
        
        if any('Path Traversal' in attack for attack in metrics['attack_types']):
            f.write("- Validate file paths and implement proper access controls\n")
        
        if len(metrics['high_frequency_ips']) > 0:
            f.write("- Implement rate limiting to prevent DDoS attacks\n")
        
        if auth_failures > 0:
            f.write("- Enhance authentication security with account lockouts and MFA\n")
        
        f.write("- Keep all software and dependencies updated\n")
        f.write("- Consider implementing a Web Application Firewall (WAF)\n")
        f.write("- Schedule regular security audits and penetration testing\n")
    
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
        
        # Generate HTML report
        html_report_file = generate_security_report(project_name, metrics, date_dir)
        print(f"Generated HTML security report for {project_name}: {html_report_file}")
        
        # Generate plain text report
        text_report_file = generate_plain_text_report(project_name, metrics, date_dir)
        print(f"Generated text security report for {project_name}: {text_report_file}")
        
        # Create copies in the project directory for the summary
        html_report_basename = os.path.basename(html_report_file)
        text_report_basename = os.path.basename(text_report_file)
        shutil.copy(html_report_file, os.path.join(project_dir, html_report_basename))
        shutil.copy(text_report_file, os.path.join(project_dir, text_report_basename))
    
    print("Security analysis completed successfully.")

if __name__ == "__main__":
    main()
