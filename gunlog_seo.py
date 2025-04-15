#!/usr/bin/env python3
"""
Website SEO Analyzer

This script analyzes access logs for web projects and creates reports showing
search engine optimization metrics, search engine bot activity, and keyword insights.

Usage:
    python seo_analyzer.py

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
import urllib.parse
from collections import Counter, defaultdict
from urllib.parse import urlparse, parse_qs

# Import configuration
try:
    from config import PROJECTS_CSV, OUTPUT_BASE_DIR, DATE_FORMAT
except ImportError:
    print("Error: config.py file not found! Please create it with the required settings.")
    exit(1)

# Regular expression for parsing access logs
# This pattern matches the common Apache/Nginx combined log format
LOG_PATTERN = r'(.*?) - (.*?) \[(.*?)\] "(.*?)" (\d+) (\d+|-) "(.*?)" "(.*?)"'

# Search engine bot patterns
SE_BOTS = {
    'Googlebot': [
        r'(?i)googlebot',
        r'(?i)google-site-verification',
        r'(?i)google web preview',
        r'(?i)google favicon'
    ],
    'Bingbot': [
        r'(?i)bingbot',
        r'(?i)msnbot',
        r'(?i)adidxbot',
        r'(?i)bingpreview'
    ],
    'Yandex': [
        r'(?i)yandex',
        r'(?i)yandexbot',
        r'(?i)yandeximages'
    ],
    'Baidu': [
        r'(?i)baiduspider',
        r'(?i)baidu'
    ],
    'DuckDuckGo': [
        r'(?i)duckduckbot',
        r'(?i)duckduckgo'
    ],
    'Yahoo': [
        r'(?i)yahoo! slurp',
        r'(?i)yahooseeker'
    ],
    'Other': [
        r'(?i)ahrefsbot',
        r'(?i)semrushbot',
        r'(?i)mj12bot',
        r'(?i)dotbot',
        r'(?i)blexbot',
        r'(?i)seznambot'
    ]
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

def identify_bot(user_agent):
    """
    Identify search engine bot from user agent.
    
    Args:
        user_agent: User agent string
        
    Returns:
        str: Bot name or None if not a known bot
    """
    for bot_name, patterns in SE_BOTS.items():
        for pattern in patterns:
            if re.search(pattern, user_agent):
                return bot_name
    return None

def extract_search_engine(referrer):
    """
    Extract search engine and search query from a referrer URL.
    
    Args:
        referrer: Referrer URL
        
    Returns:
        tuple: (search_engine, query, organic)
    """
    if not referrer or referrer == '-':
        return None, None, False
    
    try:
        parsed_url = urlparse(referrer)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        query_params = parse_qs(parsed_url.query)
        
        # Define search engines and their query parameters
        search_engines = {
            'google': {
                'domains': ['google.com', 'google.co', 'google.'],
                'params': ['q', 'query'],
                'organic_path': '/search'
            },
            'bing': {
                'domains': ['bing.com'],
                'params': ['q'],
                'organic_path': '/search'
            },
            'yahoo': {
                'domains': ['yahoo.com', 'search.yahoo'],
                'params': ['p'],
                'organic_path': '/search'
            },
            'yandex': {
                'domains': ['yandex.', 'yandex.ru', 'yandex.com'],
                'params': ['text'],
                'organic_path': '/search'
            },
            'baidu': {
                'domains': ['baidu.com'],
                'params': ['wd', 'word'],
                'organic_path': '/s'
            },
            'duckduckgo': {
                'domains': ['duckduckgo.com'],
                'params': ['q'],
                'organic_path': '/'
            },
        }
        
        # Check against each search engine
        for engine, config in search_engines.items():
            # Check if domain matches
            if any(d in domain for d in config['domains']):
                # Check if organic path matches
                is_organic = config['organic_path'] in path
                
                # Extract search query
                query = None
                for param in config['params']:
                    if param in query_params:
                        query = query_params[param][0]
                        break
                
                return engine, query, is_organic
        
        return None, None, False
    
    except:
        return None, None, False

def parse_access_log(access_log_file):
    """
    Parse access log file and extract SEO metrics.
    
    Returns:
        dict: Dictionary with SEO metrics
    """
    log_pattern = re.compile(LOG_PATTERN)
    
    # Initialize metrics
    metrics = {
        'total_requests': 0,
        'bot_requests': 0,
        'bot_requests_by_se': Counter(),
        'crawled_urls': defaultdict(set),
        'crawl_frequency': defaultdict(Counter),
        'bot_activity_by_hour': defaultdict(Counter),
        'bot_activity_by_day': defaultdict(Counter),
        'search_engine_traffic': Counter(),
        'search_queries': Counter(),
        'organic_landing_pages': Counter(),
        'search_engine_referrers': defaultdict(Counter),
        'search_keywords_by_page': defaultdict(Counter),
        'mobile_vs_desktop': {
            'mobile': 0,
            'desktop': 0
        },
        'page_load_times': defaultdict(list),
        'urls_by_status': defaultdict(Counter),
        'status_codes': Counter(),
        'page_titles': {},
        'page_meta_descriptions': {},
        'top_exit_pages': Counter(),
        'top_entry_pages': Counter(),
        'seo_issues': [],
        'http_vs_https': {
            'http': 0,
            'https': 0
        },
    }
    
    # Track sessions for entry/exit pages
    sessions = defaultdict(list)
    ip_last_seen = {}
    session_timeout = datetime.timedelta(minutes=30)
    
    # Track bot crawl dates
    bot_last_crawl = defaultdict(dict)  # bot -> url -> timestamp
    
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
                    
                    # Parse timestamp
                    timestamp, hour, day_of_week = parse_time(time_str)
                    
                    # Extract URL and method
                    url = ''
                    method = ''
                    request_parts = request.split(' ')
                    if len(request_parts) >= 2:
                        method = request_parts[0]
                        url = request_parts[1]
                    
                    # Track HTTP vs HTTPS 
                    if url.startswith('https://'):
                        metrics['http_vs_https']['https'] += 1
                    elif url.startswith('http://'):
                        metrics['http_vs_https']['http'] += 1
                    
                    # Track status codes
                    metrics['status_codes'][status_code] += 1
                    metrics['urls_by_status'][status_code][url] += 1
                    
                    # Check for bot user agent
                    bot_name = identify_bot(user_agent)
                    if bot_name:
                        metrics['bot_requests'] += 1
                        metrics['bot_requests_by_se'][bot_name] += 1
                        metrics['bot_activity_by_hour'][hour][bot_name] += 1
                        metrics['bot_activity_by_day'][day_of_week][bot_name] += 1
                        
                        # Track crawled URLs
                        if status_code == 200 and method == 'GET':
                            metrics['crawled_urls'][bot_name].add(url)
                            
                            # Track crawl frequency
                            if url in bot_last_crawl.get(bot_name, {}):
                                last_crawl = bot_last_crawl[bot_name][url]
                                days_since_last_crawl = (timestamp - last_crawl).days
                                metrics['crawl_frequency'][bot_name][url] = days_since_last_crawl
                            
                            bot_last_crawl.setdefault(bot_name, {})[url] = timestamp
                    
                    # Extract search engine referrers
                    se, query, organic = extract_search_engine(referrer)
                    if se:
                        metrics['search_engine_traffic'][se] += 1
                        
                        if query:
                            metrics['search_queries'][query.lower()] += 1
                            
                            # Track which queries lead to which pages
                            if url:
                                metrics['search_keywords_by_page'][url][query.lower()] += 1
                        
                        metrics['search_engine_referrers'][se][url] += 1
                        
                        if organic and status_code == 200:
                            metrics['organic_landing_pages'][url] += 1
                    
                    # Track mobile vs desktop
                    if 'mobile' in user_agent.lower() or 'android' in user_agent.lower() or 'iphone' in user_agent.lower():
                        metrics['mobile_vs_desktop']['mobile'] += 1
                    else:
                        metrics['mobile_vs_desktop']['desktop'] += 1
                    
                    # Track response time if available (depends on log format)
                    try:
                        # Some logs include timing info as the last field
                        if len(request_parts) > 2 and request_parts[-1].replace('.', '', 1).isdigit():
                            response_time = float(request_parts[-1])
                            metrics['page_load_times'][url].append(response_time)
                    except:
                        pass
                    
                    # Track entry and exit pages for non-bot traffic
                    if not bot_name:
                        # Check if this is a new session or continuation
                        if ip in ip_last_seen and (timestamp - ip_last_seen[ip]) < session_timeout:
                            # Continuation of session
                            sessions[ip].append((timestamp, url))
                        else:
                            # New session, record entry page
                            if status_code == 200 and method == 'GET':
                                metrics['top_entry_pages'][url] += 1
                            sessions[ip] = [(timestamp, url)]
                        
                        # Update last seen timestamp
                        ip_last_seen[ip] = timestamp
        
        # Process sessions to find exit pages
        for ip, session in sessions.items():
            if session:
                # Last URL in session is exit page
                _, exit_url = session[-1]
                metrics['top_exit_pages'][exit_url] += 1
        
        # Identify potential SEO issues
        # 404 errors for indexed pages
        for bot_name, urls in metrics['crawled_urls'].items():
            for url in urls:
                if metrics['urls_by_status'].get(404, {}).get(url, 0) > 0:
                    metrics['seo_issues'].append({
                        'issue_type': '404 for Indexed Page',
                        'url': url,
                        'search_engine': bot_name,
                        'details': f"Page is being crawled by {bot_name} but returns 404"
                    })
        
        # Crawl frequency issues
        for bot_name, url_days in metrics['crawl_frequency'].items():
            for url, days in url_days.items():
                if days > 30:  # Not crawled in over a month
                    metrics['seo_issues'].append({
                        'issue_type': 'Low Crawl Frequency',
                        'url': url,
                        'search_engine': bot_name,
                        'details': f"Not crawled by {bot_name} in {days} days"
                    })
        
        # Non-HTTPS URLs
        if metrics['http_vs_https']['http'] > 0:
            metrics['seo_issues'].append({
                'issue_type': 'Non-HTTPS URLs',
                'url': None,
                'search_engine': None,
                'details': f"Found {metrics['http_vs_https']['http']} HTTP (non-secure) URLs"
            })
        
        print(f"Processed {line_count} lines, matched {match_count} entries")
    except Exception as e:
        print(f"Error reading log file {access_log_file}: {e}")
        return None
    
    return metrics

def generate_seo_report(project_name, metrics, output_dir):
    """Generate an HTML report of SEO metrics."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"seo_report_{today}.html")
    
    # Calculate overall SEO score
    seo_score = 100
    
    # Deduct points for various issues
    if metrics['seo_issues']:
        seo_score -= min(30, len(metrics['seo_issues']) * 5)
    
    # Deduct for low bot activity
    if metrics['bot_requests'] == 0:
        seo_score -= 20
    elif metrics['bot_requests'] < 100:
        seo_score -= 10
    
    # Deduct for HTTP URLs
    if metrics['http_vs_https']['http'] > 0:
        http_ratio = metrics['http_vs_https']['http'] / (metrics['http_vs_https']['http'] + metrics['http_vs_https']['https'] or 1)
        seo_score -= min(20, int(http_ratio * 20))
    
    # Limit score to range 0-100
    seo_score = max(0, min(100, seo_score))
    
    # Determine SEO status based on score
    if seo_score >= 90:
        seo_status = 'Excellent'
        status_color = '#4caf50'
    elif seo_score >= 70:
        seo_status = 'Good'
        status_color = '#8bc34a'
    elif seo_score >= 50:
        seo_status = 'Fair'
        status_color = '#ff9800'
    else:
        seo_status = 'Poor'
        status_color = '#f44336'
    
    # Convert days of week to names
    days_of_week = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>SEO Report for {project_name} - {today}</title>
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
        .chart-container {{ 
            height: 300px; 
            width: 100%; 
            margin-bottom: 20px; 
        }}
        .issue-box {{
            border-left: 4px solid #f44336;
            background-color: #ffebee;
            padding: 10px;
            margin-bottom: 10px;
        }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f44336; }}
        .medium {{ color: #ff9800; }}
        .low {{ color: #4caf50; }}
        .progress-bar {{ 
            height: 20px; 
            background-color: #e0e0e0; 
            border-radius: 10px; 
            margin-top: 5px;
            overflow: hidden;
        }}
        .progress-fill {{ 
            height: 100%; 
            background-color: {status_color}; 
            width: {seo_score}%;
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

    <h1>SEO Report for {project_name}</h1>
    <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="tabs">
        <div id="tab-overview" class="tab active" onclick="showTab('overview')">Overview</div>
        <div id="tab-crawling" class="tab" onclick="showTab('crawling')">Crawler Activity</div>
        <div id="tab-organic" class="tab" onclick="showTab('organic')">Organic Traffic</div>
        <div id="tab-keywords" class="tab" onclick="showTab('keywords')">Keywords</div>
        <div id="tab-issues" class="tab" onclick="showTab('issues')">SEO Issues</div>
    </div>
    
    <div id="overview" class="tab-content active">
        <div class="metric-card">
            <h2 class="metric-title">SEO Score</h2>
            <h3>{seo_status} - {seo_score}/100</h3>
            <div class="progress-bar">
                <div class="progress-fill"></div>
            </div>
            
            <div style="margin-top: 20px;">
                <table>
                    <tr>
                        <th>Metric</th>
                        <th>Value</th>
                    </tr>
                    <tr>
                        <td>Total Bot Requests</td>
                        <td>{metrics['bot_requests']}</td>
                    </tr>
                    <tr>
                        <td>Organic Search Traffic</td>
                        <td>{sum(metrics['search_engine_traffic'].values())}</td>
                    </tr>
                    <tr>
                        <td>Unique Keywords</td>
                        <td>{len(metrics['search_queries'])}</td>
                    </tr>
                    <tr>
                        <td>SEO Issues</td>
                        <td>{len(metrics['seo_issues'])}</td>
                    </tr>
                    <tr>
                        <td>HTTP vs HTTPS</td>
                        <td>HTTPS: {metrics['http_vs_https']['https']} | HTTP: {metrics['http_vs_https']['http']}</td>
                    </tr>
                    <tr>
                        <td>Mobile vs Desktop</td>
                        <td>Mobile: {metrics['mobile_vs_desktop']['mobile']} | Desktop: {metrics['mobile_vs_desktop']['desktop']}</td>
                    </tr>
                </table>
            </div>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Search Engine Bot Activity</h2>
            <div class="chart-container">
                <canvas id="bot-activity-chart"></canvas>
            </div>
            <table>
                <tr>
                    <th>Search Engine</th>
                    <th>Requests</th>
                    <th>Percentage</th>
                </tr>
"""
    
    # Add bot activity rows
    total_bot_requests = sum(metrics['bot_requests_by_se'].values()) or 1  # Avoid division by zero
    for bot, count in metrics['bot_requests_by_se'].most_common():
        percentage = (count / total_bot_requests) * 100
        html_content += f"""
                <tr>
                    <td>{bot}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Organic Search Traffic</h2>
            <div class="chart-container">
                <canvas id="search-traffic-chart"></canvas>
            </div>
            <table>
                <tr>
                    <th>Search Engine</th>
                    <th>Visits</th>
                    <th>Percentage</th>
                </tr>
"""
    
    # Add search traffic rows
    total_search_traffic = sum(metrics['search_engine_traffic'].values()) or 1  # Avoid division by zero
    for engine, count in metrics['search_engine_traffic'].most_common():
        percentage = (count / total_search_traffic) * 100
        html_content += f"""
                <tr>
                    <td>{engine.capitalize()}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
    </div>
    
    <div id="crawling" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Crawler Activity by Hour</h2>
            <div class="chart-container">
                <canvas id="hourly-crawler-chart"></canvas>
            </div>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Crawler Activity by Day</h2>
            <div class="chart-container">
                <canvas id="daily-crawler-chart"></canvas>
            </div>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Top Crawled URLs</h2>
            <p>URLs most frequently visited by search engine bots.</p>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Search Engines</th>
                    <th>Crawl Frequency</th>
                </tr>
"""
    
    # Count URLs by bot crawls
    url_crawl_count = Counter()
    for bot, urls in metrics['crawled_urls'].items():
        for url in urls:
            url_crawl_count[url] += 1
    
    # Add top crawled URLs
    for url, count in url_crawl_count.most_common(20):
        # Determine which bots crawl this URL
        crawling_bots = []
        for bot, urls in metrics['crawled_urls'].items():
            if url in urls:
                crawling_bots.append(bot)
        
        # Get average crawl frequency if available
        crawl_frequency = []
        for bot, url_days in metrics['crawl_frequency'].items():
            if url in url_days:
                crawl_frequency.append(url_days[url])
        
        avg_frequency = "Unknown"
        if crawl_frequency:
            avg_days = sum(crawl_frequency) / len(crawl_frequency)
            avg_frequency = f"{avg_days:.1f} days"
        
        html_content += f"""
                <tr>
                    <td>{url}</td>
                    <td>{', '.join(crawling_bots)}</td>
                    <td>{avg_frequency}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Crawler Status Codes</h2>
            <p>HTTP status codes returned to search engine crawlers.</p>
            <table>
                <tr>
                    <th>Status Code</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
"""
    
    # Calculate status codes for bot requests
    bot_status_codes = Counter()
    for status, urls in metrics['urls_by_status'].items():
        status_count = 0
        for url in urls:
            for bot, crawled_urls in metrics['crawled_urls'].items():
                if url in crawled_urls:
                    status_count += urls[url]
        
        if status_count > 0:
            bot_status_codes[status] = status_count
    
    # Add status code rows
    total_bot_statuses = sum(bot_status_codes.values()) or 1  # Avoid division by zero
    for status, count in sorted(bot_status_codes.items()):
        percentage = (count / total_bot_statuses) * 100
        status_class = ""
        if status >= 400:
            status_class = "critical"
        elif status >= 300:
            status_class = "medium"
        
        html_content += f"""
                <tr>
                    <td class="{status_class}">{status}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
    </div>
    
    <div id="organic" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Top Landing Pages from Search</h2>
            <p>Pages that receive the most organic search traffic.</p>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Organic Visits</th>
                    <th>Top Search Engine</th>
                </tr>
"""
    
    # Add organic landing page rows
    for url, count in metrics['organic_landing_pages'].most_common(20):
        # Find top search engine for this URL
        top_se = None
        top_se_count = 0
        for se, urls in metrics['search_engine_referrers'].items():
            if url in urls and urls[url] > top_se_count:
                top_se = se
                top_se_count = urls[url]
        
        html_content += f"""
                <tr>
                    <td>{url}</td>
                    <td>{count}</td>
                    <td>{top_se.capitalize() if top_se else 'Unknown'}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Search Engine Distribution</h2>
            <p>Breakdown of organic traffic by search engine.</p>
            <table>
                <tr>
                    <th>Search Engine</th>
                    <th>Visits</th>
                    <th>Top Landing Page</th>
                </tr>
"""
    
    # Add search engine distribution rows
    for se, count in metrics['search_engine_traffic'].most_common():
        # Find top landing page for this search engine
        top_url = None
        top_url_count = 0
        for url, url_count in metrics['search_engine_referrers'].get(se, {}).items():
            if url_count > top_url_count:
                top_url = url
                top_url_count = url_count
        
        html_content += f"""
                <tr>
                    <td>{se.capitalize()}</td>
                    <td>{count}</td>
                    <td>{top_url or 'N/A'}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Mobile vs Desktop</h2>
            <div class="chart-container">
                <canvas id="mobile-desktop-chart"></canvas>
            </div>
            <table>
                <tr>
                    <th>Device Type</th>
                    <th>Visits</th>
                    <th>Percentage</th>
                </tr>
"""
    
    # Add mobile vs desktop rows
    total_visits = metrics['mobile_vs_desktop']['mobile'] + metrics['mobile_vs_desktop']['desktop'] or 1
    mobile_percent = (metrics['mobile_vs_desktop']['mobile'] / total_visits) * 100
    desktop_percent = (metrics['mobile_vs_desktop']['desktop'] / total_visits) * 100
    
    html_content += f"""
                <tr>
                    <td>Mobile</td>
                    <td>{metrics['mobile_vs_desktop']['mobile']}</td>
                    <td>{mobile_percent:.1f}%</td>
                </tr>
                <tr>
                    <td>Desktop</td>
                    <td>{metrics['mobile_vs_desktop']['desktop']}</td>
                    <td>{desktop_percent:.1f}%</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
    </div>
    
    <div id="keywords" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Top Search Keywords</h2>
            <p>Most common search terms bringing visitors to your site.</p>
            <table>
                <tr>
                    <th>Keyword</th>
                    <th>Searches</th>
                    <th>Top Landing Page</th>
                </tr>
"""
    
    # Add top keywords rows
    for keyword, count in metrics['search_queries'].most_common(20):
        # Find top landing page for this keyword
        top_page = None
        top_page_count = 0
        for page, keywords in metrics['search_keywords_by_page'].items():
            if keyword in keywords and keywords[keyword] > top_page_count:
                top_page = page
                top_page_count = keywords[keyword]
        
        html_content += f"""
                <tr>
                    <td>{keyword}</td>
                    <td>{count}</td>
                    <td>{top_page or 'Unknown'}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Keywords by Page</h2>
            <p>Search keywords bringing visitors to specific pages.</p>
"""
    
    # Add keywords by page section
    for url, keywords in sorted(metrics['search_keywords_by_page'].items(), 
                              key=lambda x: sum(x[1].values()), reverse=True)[:10]:
        html_content += f"""
            <h3>{url}</h3>
            <table>
                <tr>
                    <th>Keyword</th>
                    <th>Searches</th>
                </tr>
"""
        
        for keyword, count in keywords.most_common(5):
            html_content += f"""
                <tr>
                    <td>{keyword}</td>
                    <td>{count}</td>
                </tr>
"""
        
        html_content += """
            </table>
"""
    
    html_content += """
        </div>
    </div>
    
    <div id="issues" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">SEO Issues</h2>
            <p>Potential problems affecting your search engine visibility.</p>
"""
    
    if not metrics['seo_issues']:
        html_content += """
            <p>No significant SEO issues detected!</p>
"""
    else:
        for issue in metrics['seo_issues']:
            html_content += f"""
            <div class="issue-box">
                <h3>{issue['issue_type']}</h3>
                <p>{issue['details']}</p>
                {f"<p><strong>URL:</strong> {issue['url']}</p>" if issue['url'] else ""}
                {f"<p><strong>Search Engine:</strong> {issue['search_engine']}</p>" if issue['search_engine'] else ""}
            </div>
"""
    
    html_content += """
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Recommendations</h2>
"""
    
    # Add recommendations based on issues
    if metrics['http_vs_https']['http'] > 0:
        html_content += """
            <div class="rec-box">
                <h3>Switch to HTTPS</h3>
                <p>Secure your website by moving all content to HTTPS. Search engines prioritize secure websites in rankings.</p>
            </div>
"""
    
    if any(issue['issue_type'] == '404 for Indexed Page' for issue in metrics['seo_issues']):
        html_content += """
            <div class="rec-box">
                <h3>Fix 404 Errors for Indexed Pages</h3>
                <p>Implement 301 redirects for indexed pages that return 404 errors to preserve SEO value.</p>
            </div>
"""
    
    if any(issue['issue_type'] == 'Low Crawl Frequency' for issue in metrics['seo_issues']):
        html_content += """
            <div class="rec-box">
                <h3>Improve Crawlability</h3>
                <p>Update your sitemap.xml, optimize internal linking, and ensure robots.txt doesn't block important content.</p>
            </div>
"""
    
    # Add general recommendations
    html_content += """
            <div class="rec-box">
                <h3>Mobile Optimization</h3>
                <p>Ensure your website is fully responsive and mobile-friendly to improve rankings on mobile searches.</p>
            </div>
            
            <div class="rec-box">
                <h3>Page Speed Optimization</h3>
                <p>Improve loading times by optimizing images, leveraging browser caching, and minimizing code.</p>
            </div>
            
            <div class="rec-box">
                <h3>Content Quality</h3>
                <p>Create high-quality, relevant content that answers users' search queries to improve rankings.</p>
            </div>
        </div>
    </div>
    
    <script>
        // Bot activity chart
        const botCtx = document.getElementById('bot-activity-chart').getContext('2d');
        const botChart = new Chart(botCtx, {
            type: 'pie',
            data: {
                labels: [
"""
    
    # Add bot labels
    for bot, _ in metrics['bot_requests_by_se'].most_common():
        html_content += f"                    '{bot}',\n"
    
    html_content += """
                ],
                datasets: [{
                    data: [
"""
    
    # Add bot counts
    for _, count in metrics['bot_requests_by_se'].most_common():
        html_content += f"                        {count},\n"
    
    html_content += """
                    ],
                    backgroundColor: [
                        '#4285F4',  /* Google blue */
                        '#00a1f1',  /* Bing blue */
                        '#ff0000',  /* Yandex red */
                        '#2376B7',  /* Baidu blue */
                        '#DE5833',  /* DuckDuckGo orange */
                        '#5F01D1',  /* Yahoo purple */
                        '#999999'   /* Other */
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
                        text: 'Search Engine Bot Distribution'
                    }
                }
            }
        });
        
        // Search traffic chart
        const searchCtx = document.getElementById('search-traffic-chart').getContext('2d');
        const searchChart = new Chart(searchCtx, {
            type: 'pie',
            data: {
                labels: [
"""
    
    # Add search engine labels
    for engine, _ in metrics['search_engine_traffic'].most_common():
        html_content += f"                    '{engine.capitalize()}',\n"
    
    html_content += """
                ],
                datasets: [{
                    data: [
"""
    
    # Add search engine counts
    for _, count in metrics['search_engine_traffic'].most_common():
        html_content += f"                        {count},\n"
    
    html_content += """
                    ],
                    backgroundColor: [
                        '#4285F4',  /* Google blue */
                        '#00a1f1',  /* Bing blue */
                        '#ff0000',  /* Yandex red */
                        '#2376B7',  /* Baidu blue */
                        '#DE5833',  /* DuckDuckGo orange */
                        '#5F01D1'   /* Yahoo purple */
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
                        text: 'Organic Traffic by Search Engine'
                    }
                }
            }
        });
        
        // Mobile vs desktop chart
        const deviceCtx = document.getElementById('mobile-desktop-chart').getContext('2d');
        const deviceChart = new Chart(deviceCtx, {
            type: 'pie',
            data: {
                labels: [
                    'Mobile',
                    'Desktop'
                ],
                datasets: [{
                    data: [
                        {metrics['mobile_vs_desktop']['mobile']},
                        {metrics['mobile_vs_desktop']['desktop']}
                    ],
                    backgroundColor: [
                        '#ff9800',  /* Mobile - Orange */
                        '#2196f3'   /* Desktop - Blue */
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
                        text: 'Mobile vs Desktop Traffic'
                    }
                }
            }
        });
        
        // Hourly crawler activity chart
        const hourlyCtx = document.getElementById('hourly-crawler-chart').getContext('2d');
        const hourlyChart = new Chart(hourlyCtx, {
            type: 'bar',
            data: {
                labels: [
"""
    
    # Add hour labels
    for hour in range(24):
        html_content += f"                    '{hour:02d}:00',\n"
    
    html_content += """
                ],
                datasets: [
"""
    
    # Add dataset for each bot
    colors = ['#4285F4', '#00a1f1', '#ff0000', '#2376B7', '#DE5833', '#5F01D1', '#999999']
    for i, (bot_name, _) in enumerate(metrics['bot_requests_by_se'].most_common()):
        color = colors[i % len(colors)]
        
        html_content += f"""
                    {{
                        label: '{bot_name}',
                        data: [
"""
        
        # Add hourly data for this bot
        for hour in range(24):
            count = metrics['bot_activity_by_hour'].get(hour, {}).get(bot_name, 0)
            html_content += f"                            {count},\n"
        
        html_content += f"""
                        ],
                        backgroundColor: '{color}',
                        borderColor: '{color}',
                        borderWidth: 1
                    }},
"""
    
    html_content += """
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        stacked: true,
                        title: {
                            display: true,
                            text: 'Hour of Day'
                        }
                    },
                    y: {
                        stacked: true,
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Requests'
                        }
                    }
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Bot Activity by Hour'
                    }
                }
            }
        });
        
        // Daily crawler activity chart
        const dailyCtx = document.getElementById('daily-crawler-chart').getContext('2d');
        const dailyChart = new Chart(dailyCtx, {
            type: 'bar',
            data: {
                labels: [
"""
    
    # Add day labels
    for day in days_of_week:
        html_content += f"                    '{day}',\n"
    
    html_content += """
                ],
                datasets: [
"""
    
    # Add dataset for each bot
    for i, (bot_name, _) in enumerate(metrics['bot_requests_by_se'].most_common()):
        color = colors[i % len(colors)]
        
        html_content += f"""
                    {{
                        label: '{bot_name}',
                        data: [
"""
        
        # Add daily data for this bot
        for day_idx in range(7):
            count = metrics['bot_activity_by_day'].get(day_idx, {}).get(bot_name, 0)
            html_content += f"                            {count},\n"
        
        html_content += f"""
                        ],
                        backgroundColor: '{color}',
                        borderColor: '{color}',
                        borderWidth: 1
                    }},
"""
    
    html_content += """
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        stacked: true,
                        title: {
                            display: true,
                            text: 'Day of Week'
                        }
                    },
                    y: {
                        stacked: true,
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Requests'
                        }
                    }
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Bot Activity by Day'
                    }
                }
            }
        });
        
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
    """Generate a plain text report of SEO metrics."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"seo_report_{today}.txt")
    
    # Calculate SEO score
    seo_score = 100
    
    # Deduct points for various issues
    if metrics['seo_issues']:
        seo_score -= min(30, len(metrics['seo_issues']) * 5)
    
    # Deduct for low bot activity
    if metrics['bot_requests'] == 0:
        seo_score -= 20
    elif metrics['bot_requests'] < 100:
        seo_score -= 10
    
    # Deduct for HTTP URLs
    if metrics['http_vs_https']['http'] > 0:
        http_ratio = metrics['http_vs_https']['http'] / (metrics['http_vs_https']['http'] + metrics['http_vs_https']['https'] or 1)
        seo_score -= min(20, int(http_ratio * 20))
    
    # Limit score to range 0-100
    seo_score = max(0, min(100, seo_score))
    
    # Determine SEO status based on score
    if seo_score >= 90:
        seo_status = 'Excellent'
    elif seo_score >= 70:
        seo_status = 'Good'
    elif seo_score >= 50:
        seo_status = 'Fair'
    else:
        seo_status = 'Poor'
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f"SEO Report for {project_name}\n")
        f.write("="*50 + "\n")
        f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # SEO Overview
        f.write("SEO OVERVIEW\n")
        f.write("-"*50 + "\n")
        f.write(f"SEO Score: {seo_score}/100 ({seo_status})\n")
        f.write(f"Total Bot Requests: {metrics['bot_requests']}\n")
        f.write(f"Organic Search Traffic: {sum(metrics['search_engine_traffic'].values())}\n")
        f.write(f"Unique Keywords: {len(metrics['search_queries'])}\n")
        f.write(f"Mobile Traffic: {metrics['mobile_vs_desktop']['mobile']} ({(metrics['mobile_vs_desktop']['mobile'] / (metrics['mobile_vs_desktop']['mobile'] + metrics['mobile_vs_desktop']['desktop'] or 1) * 100):.1f}%)\n")
        f.write(f"HTTP URLs: {metrics['http_vs_https']['http']}\n")
        f.write(f"SEO Issues: {len(metrics['seo_issues'])}\n\n")
        
        # Bot Activity
        f.write("SEARCH ENGINE BOT ACTIVITY\n")
        f.write("-"*50 + "\n")
        for bot, count in metrics['bot_requests_by_se'].most_common():
            f.write(f"{bot}: {count}\n")
        f.write("\n")
        
        # Organic Search
        f.write("ORGANIC SEARCH TRAFFIC\n")
        f.write("-"*50 + "\n")
        for engine, count in metrics['search_engine_traffic'].most_common():
            f.write(f"{engine.capitalize()}: {count}\n")
        f.write("\n")
        
        # Top Keywords
        f.write("TOP 10 SEARCH KEYWORDS\n")
        f.write("-"*50 + "\n")
        for keyword, count in metrics['search_queries'].most_common(10):
            f.write(f"{keyword}: {count}\n")
        f.write("\n")
        
        # Top Landing Pages
        f.write("TOP 10 ORGANIC LANDING PAGES\n")
        f.write("-"*50 + "\n")
        for url, count in metrics['organic_landing_pages'].most_common(10):
            f.write(f"{url}: {count}\n")
        f.write("\n")
        
        # SEO Issues
        f.write("SEO ISSUES\n")
        f.write("-"*50 + "\n")
        if not metrics['seo_issues']:
            f.write("No significant SEO issues detected!\n")
        else:
            for issue in metrics['seo_issues']:
                f.write(f"{issue['issue_type']}: {issue['details']}\n")
                if issue['url']:
                    f.write(f"URL: {issue['url']}\n")
                if issue['search_engine']:
                    f.write(f"Search Engine: {issue['search_engine']}\n")
                f.write("\n")
    
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
        html_report_file = generate_seo_report(project_name, metrics, date_dir)
        print(f"Generated HTML SEO report for {project_name}: {html_report_file}")
        
        # Generate plain text report
        text_report_file = generate_plain_text_report(project_name, metrics, date_dir)
        print(f"Generated text SEO report for {project_name}: {text_report_file}")
        
        # Create copies in the project directory for the summary
        html_report_basename = os.path.basename(html_report_file)
        text_report_basename = os.path.basename(text_report_file)
        shutil.copy(html_report_file, os.path.join(project_dir, html_report_basename))
        shutil.copy(text_report_file, os.path.join(project_dir, text_report_basename))
    
    print("SEO analysis completed successfully.")

if __name__ == "__main__":
    main()
