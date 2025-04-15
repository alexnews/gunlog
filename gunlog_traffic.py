#!/usr/bin/env python3
"""
Website Traffic Analyzer

This script analyzes access logs for web projects and creates reports showing
visitor behavior, traffic sources, and engagement metrics.

Usage:
    python traffic_analyzer.py

Requirements:
    - Configuration file (config.py) with path settings
    - CSV file with project information
    - Access to log files specified in the CSV
    - Python packages: user-agents, geoip2 (optional)
"""

import os
import re
import csv
import datetime
import shutil
import urllib.parse
from collections import Counter, defaultdict
from urllib.parse import urlparse, parse_qs
import ipaddress

# Try to import optional packages
try:
    from user_agents import parse as ua_parse
    USER_AGENTS_AVAILABLE = True
except ImportError:
    USER_AGENTS_AVAILABLE = False
    print("Note: user-agents package not available. Install with: pip install user-agents")

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
    # Default path to GeoLite2 database - adjust as needed
    GEOIP_DB_PATH = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
except ImportError:
    GEOIP_AVAILABLE = False
    print("Note: geoip2 package not available. Install with: pip install geoip2")

# Import configuration
try:
    from config import PROJECTS_CSV, OUTPUT_BASE_DIR, DATE_FORMAT
except ImportError:
    print("Error: config.py file not found! Please create it with the required settings.")
    exit(1)

# Regular expression for parsing access logs
# This pattern matches the common Apache/Nginx combined log format
LOG_PATTERN = r'(.*?) - (.*?) \[(.*?)\] "(.*?)" (\d+) (\d+|-) "(.*?)" "(.*?)"'

# Patterns for identifying bots
BOT_PATTERNS = [
    r'bot', r'crawl', r'spider', r'slurp', r'baidu', r'bing', r'google', 
    r'yandex', r'facebook', r'archive', r'lighthouse', r'pagespeed', r'pingdom',
    r'uptimerobot', r'semrush', r'ahrefs', r'moz', r'screaming', r'yahoo'
]

def ensure_dir(directory):
    """Create directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)

def is_bot(user_agent):
    """
    Check if a user agent appears to be a bot/crawler.
    
    Args:
        user_agent: User agent string
        
    Returns:
        bool: True if it appears to be a bot, False otherwise
    """
    ua_lower = user_agent.lower()
    return any(bot in ua_lower for bot in BOT_PATTERNS)

def is_internal_ip(ip):
    """
    Check if an IP address is internal/private.
    
    Args:
        ip: IP address to check
        
    Returns:
        bool: True if it's an internal IP, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_multicast
        )
    except:
        return False

def get_country_from_ip(ip, reader=None):
    """
    Get country from IP address using GeoIP database.
    
    Args:
        ip: IP address to look up
        reader: GeoIP2 database reader
        
    Returns:
        str: Country name or "Unknown"
    """
    if not reader or not GEOIP_AVAILABLE:
        return "Unknown"
        
    try:
        response = reader.country(ip)
        return response.country.name
    except:
        return "Unknown"

def extract_search_engine(referrer):
    """
    Extract search engine and search query from a referrer URL.
    
    Args:
        referrer: Referrer URL
        
    Returns:
        tuple: (search_engine, query)
    """
    if not referrer or referrer == '-':
        return None, None
    
    parsed_url = urlparse(referrer)
    domain = parsed_url.netloc.lower()
    
    # Extract query parameters
    query_params = parse_qs(parsed_url.query)
    
    # Define search engines and their query parameters
    search_engines = {
        'google': ['q', 'query'],
        'bing': ['q'],
        'yahoo': ['p'],
        'yandex': ['text'],
        'baidu': ['wd', 'word'],
        'duckduckgo': ['q'],
    }
    
    # Check if the referrer is from a search engine
    for engine, params in search_engines.items():
        if engine in domain:
            for param in params:
                if param in query_params:
                    return engine, query_params[param][0]
            return engine, None
    
    return None, None

def extract_utm_params(url):
    """
    Extract UTM parameters from a URL.
    
    Args:
        url: URL to analyze
        
    Returns:
        dict: UTM parameters
    """
    if not url:
        return {}
    
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        utm_params = {}
        for param in query_params:
            if param.startswith('utm_'):
                utm_params[param] = query_params[param][0]
        
        return utm_params
    except:
        return {}

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

def classify_referrer(referrer):
    """
    Classify a referrer into a category.
    
    Args:
        referrer: Referrer URL
        
    Returns:
        str: Referrer category
    """
    if not referrer or referrer == '-' or referrer == '':
        return "Direct"
    
    parsed_url = urlparse(referrer)
    domain = parsed_url.netloc.lower()
    
    # Social media
    social_domains = [
        'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
        'pinterest.com', 'reddit.com', 't.co', 'youtube.com', 'tiktok.com'
    ]
    
    # Search engines
    search_domains = [
        'google.', 'bing.com', 'yahoo.com', 'yandex.', 'baidu.com',
        'duckduckgo.com', 'search.'
    ]
    
    # Advertising
    ad_domains = [
        'doubleclick.net', 'adwords', 'analytics', 'googleadservices',
        'ad.', 'ads.', 'advert', 'campaign'
    ]
    
    for d in social_domains:
        if d in domain:
            return "Social"
    
    for d in search_domains:
        if d in domain:
            return "Search"
    
    for d in ad_domains:
        if d in domain:
            return "Advertising"
    
    # Check for utm_source parameter
    query_params = parse_qs(parsed_url.query)
    if 'utm_source' in query_params:
        source = query_params['utm_source'][0].lower()
        if any(s in source for s in ['email', 'newsletter', 'mail']):
            return "Email"
        if any(s in source for s in ['social', 'facebook', 'twitter', 'instagram']):
            return "Social"
        if any(s in source for s in ['ad', 'advert', 'campaign', 'banner']):
            return "Advertising"
    
    return "Referral"

def parse_access_log(access_log_file):
    """
    Parse access log file and extract traffic metrics.
    
    Returns:
        dict: Dictionary with traffic metrics
    """
    log_pattern = re.compile(LOG_PATTERN)
    
    # Initialize metrics
    metrics = {
        'total_hits': 0,
        'unique_ips': set(),
        'unique_visitors': set(),  # IP + User Agent combinations
        'user_agents': Counter(),
        'browsers': Counter(),
        'os': Counter(),
        'devices': Counter(),
        'bot_hits': 0,
        'human_hits': 0,
        'hourly_traffic': Counter(),
        'daily_traffic': Counter(),
        'status_codes': Counter(),
        'pages': Counter(),
        'entry_pages': Counter(),
        'exit_pages': Counter(),
        'referrers': Counter(),
        'referrer_types': Counter(),
        'search_engines': Counter(),
        'search_keywords': Counter(),
        'countries': Counter(),
        'utm_sources': Counter(),
        'utm_mediums': Counter(),
        'utm_campaigns': Counter(),
        'file_types': Counter(),
        'sessions': defaultdict(list),  # IP -> list of requests
        'paths': [],  # List of (timestamp, IP, URL, session_id)
    }
    
    # Initialize GeoIP reader if available
    geoip_reader = None
    if GEOIP_AVAILABLE and os.path.exists(GEOIP_DB_PATH):
        try:
            geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        except:
            print(f"Warning: Could not initialize GeoIP database from {GEOIP_DB_PATH}")
    
    line_count = 0
    match_count = 0
    skipped_count = 0
    
    # Keep track of IP sessions (last seen timestamp)
    ip_sessions = {}
    session_timeout = datetime.timedelta(minutes=30)
    
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
                    if is_internal_ip(ip):
                        skipped_count += 1
                        continue
                    
                    # Parse timestamp
                    timestamp, hour, day_of_week = parse_time(time_str)
                    
                    # Extract request method and URL
                    request_parts = request.split()
                    if len(request_parts) >= 2:
                        method = request_parts[0]
                        url = request_parts[1]
                    else:
                        method = "UNKNOWN"
                        url = "UNKNOWN"
                    
                    # Skip static files and focus on pages
                    file_ext = os.path.splitext(url)[1].lower()
                    metrics['file_types'][file_ext if file_ext else '(none)'] += 1
                    
                    static_extensions = [
                        '.jpg', '.jpeg', '.png', '.gif', '.ico', '.css', 
                        '.js', '.svg', '.woff', '.woff2', '.ttf', '.eot'
                    ]
                    is_static = file_ext in static_extensions
                    
                    # Count hits
                    metrics['total_hits'] += 1
                    metrics['unique_ips'].add(ip)
                    visitor_id = f"{ip}|{user_agent}"
                    metrics['unique_visitors'].add(visitor_id)
                    
                    # Determine if this is a bot
                    is_bot_ua = is_bot(user_agent)
                    
                    if is_bot_ua:
                        metrics['bot_hits'] += 1
                    else:
                        metrics['human_hits'] += 1
                    
                    # Track user agent
                    metrics['user_agents'][user_agent] += 1
                    
                    # Parse user agent details if package is available
                    if USER_AGENTS_AVAILABLE and not is_bot_ua:
                        try:
                            ua = ua_parse(user_agent)
                            browser_family = f"{ua.browser.family} {ua.browser.version_string}"
                            os_family = f"{ua.os.family} {ua.os.version_string}"
                            device_type = "Mobile" if ua.is_mobile else "Tablet" if ua.is_tablet else "Desktop"
                            
                            metrics['browsers'][browser_family] += 1
                            metrics['os'][os_family] += 1
                            metrics['devices'][device_type] += 1
                        except:
                            pass
                    
                    # Track time patterns
                    metrics['hourly_traffic'][hour] += 1
                    metrics['daily_traffic'][day_of_week] += 1
                    
                    # Track status codes
                    metrics['status_codes'][status_code] += 1
                    
                    # Track page views (exclude static files and non-200 responses)
                    if not is_static and status_code == 200 and method == "GET":
                        metrics['pages'][url] += 1
                    
                    # Track referrers
                    if referrer != '-' and referrer != '':
                        metrics['referrers'][referrer] += 1
                        referrer_type = classify_referrer(referrer)
                        metrics['referrer_types'][referrer_type] += 1
                        
                        # Extract search engine and keyword
                        search_engine, keyword = extract_search_engine(referrer)
                        if search_engine:
                            metrics['search_engines'][search_engine] += 1
                            if keyword:
                                metrics['search_keywords'][keyword.lower()] += 1
                    else:
                        metrics['referrer_types']['Direct'] += 1
                    
                    # Track countries
                    if geoip_reader:
                        country = get_country_from_ip(ip, geoip_reader)
                        metrics['countries'][country] += 1
                    
                    # Extract UTM parameters
                    utm_params = extract_utm_params(url)
                    if 'utm_source' in utm_params:
                        metrics['utm_sources'][utm_params['utm_source']] += 1
                    if 'utm_medium' in utm_params:
                        metrics['utm_mediums'][utm_params['utm_medium']] += 1
                    if 'utm_campaign' in utm_params:
                        metrics['utm_campaigns'][utm_params['utm_campaign']] += 1
                    
                    # Session tracking
                    if ip in ip_sessions:
                        last_time = ip_sessions[ip]
                        # If more than 30 minutes have passed, consider it a new session
                        if timestamp - last_time > session_timeout:
                            session_id = f"{ip}_{timestamp.timestamp()}"
                            # Record previous page as exit page
                            if len(metrics['sessions'][ip]) > 0:
                                prev_url = metrics['sessions'][ip][-1][1]
                                metrics['exit_pages'][prev_url] += 1
                            # Record current page as entry page
                            if not is_static and status_code == 200:
                                metrics['entry_pages'][url] += 1
                            # Start new session
                            metrics['sessions'][ip] = [(timestamp, url, session_id)]
                        else:
                            # Continue session
                            session_id = metrics['sessions'][ip][0][2]
                            metrics['sessions'][ip].append((timestamp, url, session_id))
                    else:
                        # New session
                        session_id = f"{ip}_{timestamp.timestamp()}"
                        if not is_static and status_code == 200:
                            metrics['entry_pages'][url] += 1
                        metrics['sessions'][ip] = [(timestamp, url, session_id)]
                    
                    # Update last seen timestamp
                    ip_sessions[ip] = timestamp
                    
                    # Record path for visitor flow analysis
                    metrics['paths'].append((timestamp, ip, url, session_id))
        
        # After processing, record remaining exit pages
        for ip, session in metrics['sessions'].items():
            if len(session) > 0:
                last_url = session[-1][1]
                metrics['exit_pages'][last_url] += 1
        
        # Close GeoIP reader if used
        if geoip_reader:
            geoip_reader.close()
        
        print(f"Processed {line_count} lines, matched {match_count} entries, skipped {skipped_count} internal IPs")
    except Exception as e:
        print(f"Error reading log file {access_log_file}: {e}")
        return None
    
    return metrics

def calculate_bounce_rate(metrics):
    """
    Calculate bounce rate (visitors who viewed only one page).
    
    Args:
        metrics: Dictionary of metrics
        
    Returns:
        float: Bounce rate percentage
    """
    single_page_sessions = 0
    total_sessions = 0
    
    for ip, session in metrics['sessions'].items():
        # Count unique pages in session
        unique_pages = set()
        for _, url, _ in session:
            # Exclude static files
            file_ext = os.path.splitext(url)[1].lower()
            static_extensions = [
                '.jpg', '.jpeg', '.png', '.gif', '.ico', '.css', 
                '.js', '.svg', '.woff', '.woff2', '.ttf', '.eot'
            ]
            if file_ext not in static_extensions:
                unique_pages.add(url)
        
        # Count as bounce if only one unique page was viewed
        if len(unique_pages) == 1:
            single_page_sessions += 1
        total_sessions += 1
    
    return (single_page_sessions / total_sessions * 100) if total_sessions > 0 else 0

def calculate_visitor_flow(metrics, max_steps=5):
    """
    Calculate visitor flow through the site.
    
    Args:
        metrics: Dictionary of metrics
        max_steps: Maximum number of steps to analyze
        
    Returns:
        dict: Visitor flow data
    """
    flow = {
        'pathways': Counter(),
        'step_counts': Counter(),
        'transitions': defaultdict(Counter),
    }
    
    # Group by session ID
    session_paths = defaultdict(list)
    for timestamp, ip, url, session_id in sorted(metrics['paths']):
        # Skip static files
        file_ext = os.path.splitext(url)[1].lower()
        static_extensions = [
            '.jpg', '.jpeg', '.png', '.gif', '.ico', '.css', 
            '.js', '.svg', '.woff', '.woff2', '.ttf', '.eot'
        ]
        if file_ext not in static_extensions:
            session_paths[session_id].append(url)
    
    # Analyze paths
    for session_id, urls in session_paths.items():
        # Count steps in path
        path_length = min(len(urls), max_steps)
        flow['step_counts'][path_length] += 1
        
        # Record pathways (first 3 steps)
        if len(urls) >= 3:
            pathway = " > ".join(urls[:3])
            flow['pathways'][pathway] += 1
        
        # Record transitions between pages
        for i in range(len(urls) - 1):
            from_url = urls[i]
            to_url = urls[i + 1]
            flow['transitions'][from_url][to_url] += 1
    
    return flow

def generate_traffic_report(project_name, metrics, output_dir):
    """Generate an HTML report of traffic metrics."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"traffic_report_{today}.html")
    
    # Calculate some derived metrics
    bounce_rate = calculate_bounce_rate(metrics)
    visitor_flow = calculate_visitor_flow(metrics)
    
    # Format day names
    days_of_week = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Traffic Report for {project_name} - {today}</title>
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
        .flow-chart {{ 
            overflow-x: auto;
            margin: 20px 0;
        }}
        .flow-node {{
            display: inline-block;
            margin: 5px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            background-color: #f0f0f0;
        }}
        .flow-arrow {{
            display: inline-block;
            margin: 0 10px;
            color: #666;
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

    <h1>Traffic Report for {project_name}</h1>
    <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="tabs">
        <div id="tab-overview" class="tab active" onclick="showTab('overview')">Overview</div>
        <div id="tab-visitors" class="tab" onclick="showTab('visitors')">Visitors</div>
        <div id="tab-traffic" class="tab" onclick="showTab('traffic')">Traffic Sources</div>
        <div id="tab-content" class="tab" onclick="showTab('content')">Content</div>
        <div id="tab-behavior" class="tab" onclick="showTab('behavior')">User Behavior</div>
    </div>
    
    <div id="overview" class="tab-content active">
        <div class="metric-card">
            <h2 class="metric-title">Visitor Overview</h2>
            <table>
                <tr>
                    <th>Total Hits</th>
                    <td>{metrics['total_hits']}</td>
                </tr>
                <tr>
                    <th>Unique Visitors</th>
                    <td>{len(metrics['unique_visitors'])}</td>
                </tr>
                <tr>
                    <th>Unique IP Addresses</th>
                    <td>{len(metrics['unique_ips'])}</td>
                </tr>
                <tr>
                    <th>Human Visitors</th>
                    <td>{metrics['human_hits']} ({metrics['human_hits']/metrics['total_hits']*100:.1f}%)</td>
                </tr>
                <tr>
                    <th>Bot Traffic</th>
                    <td>{metrics['bot_hits']} ({metrics['bot_hits']/metrics['total_hits']*100:.1f}%)</td>
                </tr>
                <tr>
                    <th>Bounce Rate</th>
                    <td>{bounce_rate:.1f}%</td>
                </tr>
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Traffic Patterns</h2>
            <div class="chart-container">
                <canvas id="hourly-traffic-chart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="daily-traffic-chart"></canvas>
            </div>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Traffic Sources</h2>
            <div class="chart-container">
                <canvas id="referrer-chart"></canvas>
            </div>
        </div>
    </div>
    
    <div id="visitors" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Browsers</h2>
            <table>
                <tr>
                    <th>Browser</th>
                    <th>Hits</th>
                    <th>Percentage</th>
                </tr>
"""
    
    # Add browser rows
    for browser, count in metrics['browsers'].most_common(20):
        percentage = count / metrics['human_hits'] * 100 if metrics['human_hits'] > 0 else 0
        html_content += f"""
                <tr>
                    <td>{browser}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Operating Systems</h2>
            <table>
                <tr>
                    <th>OS</th>
                    <th>Hits</th>
                    <th>Percentage</th>
                </tr>
"""
    
    # Add OS rows
    for os_name, count in metrics['os'].most_common(20):
        percentage = count / metrics['human_hits'] * 100 if metrics['human_hits'] > 0 else 0
        html_content += f"""
                <tr>
                    <td>{os_name}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Device Types</h2>
            <div class="chart-container">
                <canvas id="device-chart"></canvas>
            </div>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Geographic Distribution</h2>
            <table>
                <tr>
                    <th>Country</th>
                    <th>Hits</th>
                    <th>Percentage</th>
                </tr>
"""
    
    # Add country rows
    for country, count in metrics['countries'].most_common(30):
        percentage = count / metrics['total_hits'] * 100 if metrics['total_hits'] > 0 else 0
        html_content += f"""
                <tr>
                    <td>{country}</td>
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
            <h2 class="metric-title">Traffic Source Categories</h2>
            <div class="chart-container">
                <canvas id="traffic-sources-chart"></canvas>
            </div>
            <table>
                <tr>
                    <th>Traffic Source</th>
                    <th>Hits</th>
                    <th>Percentage</th>
                </tr>
"""
    
    # Add referrer type rows
    for ref_type, count in metrics['referrer_types'].most_common():
        percentage = count / metrics['total_hits'] * 100 if metrics['total_hits'] > 0 else 0
        html_content += f"""
                <tr>
                    <td>{ref_type}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Top Referrers</h2>
            <table>
                <tr>
                    <th>Referrer</th>
                    <th>Hits</th>
                </tr>
"""
    
    # Add referrer rows
    for referrer, count in metrics['referrers'].most_common(20):
        html_content += f"""
                <tr>
                    <td>{referrer}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Search Engines</h2>
            <table>
                <tr>
                    <th>Search Engine</th>
                    <th>Hits</th>
                </tr>
"""
    
    # Add search engine rows
    for engine, count in metrics['search_engines'].most_common():
        html_content += f"""
                <tr>
                    <td>{engine}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Top Search Keywords</h2>
            <table>
                <tr>
                    <th>Keyword</th>
                    <th>Hits</th>
                </tr>
"""
    
    # Add search keyword rows
    for keyword, count in metrics['search_keywords'].most_common(20):
        html_content += f"""
                <tr>
                    <td>{keyword}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Campaign Tracking</h2>
            <h3>UTM Sources</h3>
            <table>
                <tr>
                    <th>UTM Source</th>
                    <th>Hits</th>
                </tr>
"""
    
    # Add UTM source rows
    for source, count in metrics['utm_sources'].most_common(10):
        html_content += f"""
                <tr>
                    <td>{source}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
            
            <h3>UTM Mediums</h3>
            <table>
                <tr>
                    <th>UTM Medium</th>
                    <th>Hits</th>
                </tr>
"""
    
    # Add UTM medium rows
    for medium, count in metrics['utm_mediums'].most_common(10):
        html_content += f"""
                <tr>
                    <td>{medium}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
            
            <h3>UTM Campaigns</h3>
            <table>
                <tr>
                    <th>UTM Campaign</th>
                    <th>Hits</th>
                </tr>
"""
    
    # Add UTM campaign rows
    for campaign, count in metrics['utm_campaigns'].most_common(10):
        html_content += f"""
                <tr>
                    <td>{campaign}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
    </div>
    
    <div id="content" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Top Pages</h2>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Views</th>
                </tr>
"""
    
    # Add page rows
    for url, count in metrics['pages'].most_common(30):
        html_content += f"""
                <tr>
                    <td>{url}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Top Entry Pages</h2>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Entries</th>
                </tr>
"""
    
    # Add entry page rows
    for url, count in metrics['entry_pages'].most_common(20):
        html_content += f"""
                <tr>
                    <td>{url}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Top Exit Pages</h2>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Exits</th>
                </tr>
"""
    
    # Add exit page rows
    for url, count in metrics['exit_pages'].most_common(20):
        html_content += f"""
                <tr>
                    <td>{url}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Content Types</h2>
            <table>
                <tr>
                    <th>File Extension</th>
                    <th>Requests</th>
                </tr>
"""
    
    # Add file type rows
    for ext, count in metrics['file_types'].most_common(20):
        html_content += f"""
                <tr>
                    <td>{ext}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
    </div>
    
    <div id="behavior" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Visitor Flow</h2>
            <h3>Session Depth</h3>
            <div class="chart-container">
                <canvas id="session-depth-chart"></canvas>
            </div>
            
            <h3>Common Pathways (First 3 Steps)</h3>
            <table>
                <tr>
                    <th>Path</th>
                    <th>Count</th>
                </tr>
"""
    
    # Add pathway rows
    for pathway, count in visitor_flow['pathways'].most_common(15):
        html_content += f"""
                <tr>
                    <td>{pathway}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
            
            <h3>Common Transitions</h3>
            <table>
                <tr>
                    <th>From</th>
                    <th>To</th>
                    <th>Count</th>
                </tr>
"""
    
    # Add transition rows
    transitions = []
    for from_url, to_counts in visitor_flow['transitions'].items():
        for to_url, count in to_counts.items():
            transitions.append((from_url, to_url, count))
    
    for from_url, to_url, count in sorted(transitions, key=lambda x: x[2], reverse=True)[:20]:
        # Truncate URLs if too long
        from_display = from_url if len(from_url) < 50 else from_url[:47] + "..."
        to_display = to_url if len(to_url) < 50 else to_url[:47] + "..."
        
        html_content += f"""
                <tr>
                    <td>{from_display}</td>
                    <td>{to_display}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Bounce Rate Analysis</h2>
            <p><strong>Overall Bounce Rate:</strong> {bounce_rate:.1f}%</p>
            <p>Bounce rate is the percentage of visitors who navigate away after viewing only one page.</p>
            
            <h3>Bounce Rate by Entry Page</h3>
            <table>
                <tr>
                    <th>Entry Page</th>
                    <th>Entries</th>
                    <th>Bounces</th>
                    <th>Bounce Rate</th>
                </tr>
"""
    
    # Compute bounces per entry page
    entry_bounces = defaultdict(int)
    
    for ip, session in metrics['sessions'].items():
        # Sort session by timestamp
        sorted_session = sorted(session, key=lambda x: x[0])
        
        if len(sorted_session) == 1:
            # This is a bounce - only one page in session
            entry_url = sorted_session[0][1]
            entry_bounces[entry_url] += 1
    
    # Add bounce rate rows for top entry pages
    for url, entries in metrics['entry_pages'].most_common(15):
        bounces = entry_bounces.get(url, 0)
        bounce_rate_page = (bounces / entries * 100) if entries > 0 else 0
        
        html_content += f"""
                <tr>
                    <td>{url}</td>
                    <td>{entries}</td>
                    <td>{bounces}</td>
                    <td>{bounce_rate_page:.1f}%</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
    </div>
    
    <script>
        // Hourly traffic chart
        const hourlyCtx = document.getElementById('hourly-traffic-chart').getContext('2d');
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
                datasets: [{
                    label: 'Requests by Hour',
                    data: [
"""
    
    # Add hourly traffic data
    for hour in range(24):
        count = metrics['hourly_traffic'].get(hour, 0)
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
                            text: 'Requests'
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
                        text: 'Traffic by Hour of Day'
                    }
                }
            }
        });
        
        // Daily traffic chart
        const dailyCtx = document.getElementById('daily-traffic-chart').getContext('2d');
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
                datasets: [{
                    label: 'Requests by Day',
                    data: [
"""
    
    # Add daily traffic data
    for day_idx in range(7):
        count = metrics['daily_traffic'].get(day_idx, 0)
        html_content += f"                        {count},\n"
    
    html_content += """
                    ],
                    backgroundColor: '#4caf50',
                    borderColor: '#388e3c',
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
                            text: 'Requests'
                        }
                    }
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Traffic by Day of Week'
                    }
                }
            }
        });
        
        // Referrer chart
        const referrerCtx = document.getElementById('referrer-chart').getContext('2d');
        const referrerChart = new Chart(referrerCtx, {
            type: 'pie',
            data: {
                labels: [
"""
    
    # Add referrer type labels
    for ref_type, _ in metrics['referrer_types'].most_common():
        html_content += f"                    '{ref_type}',\n"
    
    html_content += """
                ],
                datasets: [{
                    data: [
"""
    
    # Add referrer type counts
    for _, count in metrics['referrer_types'].most_common():
        html_content += f"                        {count},\n"
    
    html_content += """
                    ],
                    backgroundColor: [
                        '#2196f3',  /* Direct */
                        '#4caf50',  /* Search */
                        '#ff9800',  /* Referral */
                        '#e91e63',  /* Social */
                        '#9c27b0',  /* Email */
                        '#607d8b',  /* Advertising */
                        '#795548'   /* Other */
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
                        text: 'Traffic Sources'
                    }
                }
            }
        });
        
        // Traffic sources chart
        const sourcesCtx = document.getElementById('traffic-sources-chart').getContext('2d');
        const sourcesChart = new Chart(sourcesCtx, {
            type: 'doughnut',
            data: {
                labels: [
"""
    
    # Add referrer type labels again for traffic sources chart
    for ref_type, _ in metrics['referrer_types'].most_common():
        html_content += f"                    '{ref_type}',\n"
    
    html_content += """
                ],
                datasets: [{
                    data: [
"""
    
    # Add referrer type counts again for traffic sources chart
    for _, count in metrics['referrer_types'].most_common():
        html_content += f"                        {count},\n"
    
    html_content += """
                    ],
                    backgroundColor: [
                        '#2196f3',  /* Direct */
                        '#4caf50',  /* Search */
                        '#ff9800',  /* Referral */
                        '#e91e63',  /* Social */
                        '#9c27b0',  /* Email */
                        '#607d8b',  /* Advertising */
                        '#795548'   /* Other */
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
                        text: 'Traffic Source Distribution'
                    }
                }
            }
        });
        
        // Device chart
        const deviceCtx = document.getElementById('device-chart').getContext('2d');
        const deviceChart = new Chart(deviceCtx, {
            type: 'pie',
            data: {
                labels: [
"""
    
    # Add device type labels
    for device, _ in metrics['devices'].most_common():
        html_content += f"                    '{device}',\n"
    
    html_content += """
                ],
                datasets: [{
                    data: [
"""
    
    # Add device type counts
    for _, count in metrics['devices'].most_common():
        html_content += f"                        {count},\n"
    
    html_content += """
                    ],
                    backgroundColor: [
                        '#2196f3',  /* Desktop */
                        '#ff9800',  /* Mobile */
                        '#4caf50',  /* Tablet */
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
                        text: 'Device Types'
                    }
                }
            }
        });
        
        // Session depth chart
        const depthCtx = document.getElementById('session-depth-chart').getContext('2d');
        const depthChart = new Chart(depthCtx, {
            type: 'bar',
            data: {
                labels: [
"""
    
    # Add session depth labels
    for depth in range(1, 11):
        label = f"{depth} page{'s' if depth > 1 else ''}"
        html_content += f"                    '{label}',\n"
    
    html_content += """
                ],
                datasets: [{
                    label: 'Number of Sessions',
                    data: [
"""
    
    # Add session depth counts
    for depth in range(1, 11):
        count = visitor_flow['step_counts'].get(depth, 0)
        html_content += f"                        {count},\n"
    
    html_content += """
                    ],
                    backgroundColor: '#9c27b0',
                    borderColor: '#7b1fa2',
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
                            text: 'Sessions'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Number of Pages Visited'
                        }
                    }
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Session Depth'
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

def generate_plain_text_report(project_name, metrics, output_dir):
    """Generate a plain text report of traffic metrics."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"traffic_report_{today}.txt")
    
    # Calculate some derived metrics
    bounce_rate = calculate_bounce_rate(metrics)
    visitor_flow = calculate_visitor_flow(metrics)
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f"Traffic Report for {project_name}\n")
        f.write("="*50 + "\n")
        f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Visitor overview
        f.write("VISITOR OVERVIEW\n")
        f.write("-"*50 + "\n")
        f.write(f"Total Hits: {metrics['total_hits']}\n")
        f.write(f"Unique Visitors: {len(metrics['unique_visitors'])}\n")
        f.write(f"Unique IP Addresses: {len(metrics['unique_ips'])}\n")
        f.write(f"Human Visitors: {metrics['human_hits']} ({metrics['human_hits']/metrics['total_hits']*100:.1f}%)\n")
        f.write(f"Bot Traffic: {metrics['bot_hits']} ({metrics['bot_hits']/metrics['total_hits']*100:.1f}%)\n")
        f.write(f"Bounce Rate: {bounce_rate:.1f}%\n\n")
        
        # Traffic sources
        f.write("TRAFFIC SOURCES\n")
        f.write("-"*50 + "\n")
        for source_type, count in metrics['referrer_types'].most_common():
            percentage = count / metrics['total_hits'] * 100 if metrics['total_hits'] > 0 else 0
            f.write(f"{source_type}: {count} ({percentage:.1f}%)\n")
        f.write("\n")
        
        # Top pages
        f.write("TOP 20 PAGES\n")
        f.write("-"*50 + "\n")
        for i, (url, count) in enumerate(metrics['pages'].most_common(20), 1):
            f.write(f"{i}. {url} - {count} views\n")
        f.write("\n")
        
        # Top entry pages
        f.write("TOP 10 ENTRY PAGES\n")
        f.write("-"*50 + "\n")
        for i, (url, count) in enumerate(metrics['entry_pages'].most_common(10), 1):
            f.write(f"{i}. {url} - {count} entries\n")
        f.write("\n")
        
        # Top exit pages
        f.write("TOP 10 EXIT PAGES\n")
        f.write("-"*50 + "\n")
        for i, (url, count) in enumerate(metrics['exit_pages'].most_common(10), 1):
            f.write(f"{i}. {url} - {count} exits\n")
        f.write("\n")
        
        # Top referrers
        f.write("TOP 10 REFERRERS\n")
        f.write("-"*50 + "\n")
        for i, (referrer, count) in enumerate(metrics['referrers'].most_common(10), 1):
            f.write(f"{i}. {referrer} - {count} referrals\n")
        f.write("\n")
        
        # Devices
        if metrics['devices']:
            f.write("DEVICE TYPES\n")
            f.write("-"*50 + "\n")
            for device, count in metrics['devices'].most_common():
                percentage = count / sum(metrics['devices'].values()) * 100 if sum(metrics['devices'].values()) > 0 else 0
                f.write(f"{device}: {count} ({percentage:.1f}%)\n")
            f.write("\n")
        
        # Countries
        if metrics['countries']:
            f.write("TOP 10 COUNTRIES\n")
            f.write("-"*50 + "\n")
            for i, (country, count) in enumerate(metrics['countries'].most_common(10), 1):
                percentage = count / metrics['total_hits'] * 100 if metrics['total_hits'] > 0 else 0
                f.write(f"{i}. {country} - {count} hits ({percentage:.1f}%)\n")
            f.write("\n")
        
        # Traffic patterns
        f.write("HOURLY TRAFFIC PATTERN\n")
        f.write("-"*50 + "\n")
        for hour in range(24):
            count = metrics['hourly_traffic'].get(hour, 0)
            f.write(f"Hour {hour:02d}: {count} hits\n")
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
        html_report_file = generate_traffic_report(project_name, metrics, date_dir)
        print(f"Generated HTML traffic report for {project_name}: {html_report_file}")
        
        # Generate plain text report
        text_report_file = generate_plain_text_report(project_name, metrics, date_dir)
        print(f"Generated text traffic report for {project_name}: {text_report_file}")
        
        # Create copies in the project directory for the summary
        html_report_basename = os.path.basename(html_report_file)
        text_report_basename = os.path.basename(text_report_file)
        shutil.copy(html_report_file, os.path.join(project_dir, html_report_basename))
        shutil.copy(text_report_file, os.path.join(project_dir, text_report_basename))
    
    print("Traffic analysis completed successfully.")

if __name__ == "__main__":
    main()
