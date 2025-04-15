#!/usr/bin/env python3
"""
Website Content Analyzer

This script analyzes access logs for web projects and creates reports showing
content performance, engagement metrics, and content type analysis.

Usage:
    python content_analyzer.py

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
# Example: 127.0.0.1 - - [10/Oct/2023:13:55:36 +0200] "GET /index.php HTTP/1.1" 200 2326 "http://example.com/" "Mozilla/5.0" 0.002
LOG_PATTERN = r'(.*?) - (.*?) \[(.*?)\] "(.*?)" (\d+) (\d+|-) "(.*?)" "(.*?)"(?: (\d+\.\d+))?'

# Regular expression for extracting URL paths
URL_PATTERN = r'"(?:GET|POST|HEAD) ([^"\s]+)'

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

def categorize_content(url):
    """
    Categorize a URL into content types based on patterns and extensions.
    
    Args:
        url: URL to categorize
        
    Returns:
        tuple: (content_type, category, subcategory)
    """
    # Extract file extension
    file_ext = os.path.splitext(url)[1].lower()
    
    # Default values
    content_type = "Page"
    category = "Unknown"
    subcategory = "Other"
    
    # Check file extensions first
    if file_ext in ['.html', '.htm', '.php', '.asp', '.aspx', '.jsp']:
        content_type = "Page"
    elif file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.bmp']:
        content_type = "Image"
    elif file_ext in ['.css', '.scss', '.less']:
        content_type = "Style"
    elif file_ext in ['.js', '.jsx', '.ts', '.tsx']:
        content_type = "Script"
    elif file_ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
        content_type = "Document"
    elif file_ext in ['.mp3', '.mp4', '.avi', '.mov', '.webm', '.ogg', '.wav']:
        content_type = "Media"
    elif file_ext in ['.zip', '.rar', '.tar', '.gz', '.7z']:
        content_type = "Download"
    elif file_ext in ['.json', '.xml', '.csv', '.txt']:
        content_type = "Data"
    
    # Now check URL patterns for categories
    path_parts = url.strip('/').split('/')
    
    # Try to identify category/subcategory from path
    if len(path_parts) >= 1:
        category = path_parts[0].capitalize() if path_parts[0] else "Root"
        
        if len(path_parts) >= 2:
            subcategory = path_parts[1].capitalize() if path_parts[1] else "General"
    
    # Special case for common patterns
    if '/blog/' in url or '/news/' in url or '/article/' in url:
        category = "Content"
        subcategory = "Article"
    elif '/product/' in url or '/shop/' in url or '/item/' in url:
        category = "Products"
    elif '/category/' in url or '/catalog/' in url:
        category = "Categories"
    elif '/tag/' in url:
        category = "Tags"
    elif '/search/' in url:
        category = "Search"
    elif '/user/' in url or '/account/' in url or '/profile/' in url:
        category = "User"
    elif '/api/' in url:
        category = "API"
    elif '/admin/' in url or '/dashboard/' in url:
        category = "Admin"
    elif '/forum/' in url or '/community/' in url or '/discussion/' in url:
        category = "Community"
    
    return content_type, category, subcategory

def extract_title_from_url(url):
    """
    Attempt to extract a readable title from a URL.
    
    Args:
        url: URL to extract title from
        
    Returns:
        str: A readable title
    """
    # Parse the URL
    parsed_url = urlparse(url)
    path = parsed_url.path
    
    # Remove file extension if present
    path = os.path.splitext(path)[0]
    
    # Split path into segments
    segments = [s for s in path.split('/') if s]
    
    if not segments:
        return "Home Page"
    
    # Use the last segment as the title
    title = segments[-1]
    
    # Replace hyphens, underscores with spaces
    title = title.replace('-', ' ').replace('_', ' ')
    
    # Capitalize first letter of each word
    title = ' '.join(word.capitalize() for word in title.split())
    
    return title

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

def calculate_reading_time(size):
    """
    Estimate reading time based on content size.
    
    Args:
        size: Content size in bytes
        
    Returns:
        float: Estimated reading time in seconds
    """
    # Rough approximation assuming HTML content
    # Assuming average reading speed of 200 words per minute
    # and average word size of 6 bytes including markup
    if size <= 0:
        return 0
    
    words = size / 6
    reading_time_minutes = words / 200
    return reading_time_minutes * 60  # Convert to seconds

def parse_access_log(access_log_file):
    """
    Parse access log file and extract content metrics.
    
    Returns:
        dict: Dictionary with content metrics
    """
    log_pattern = re.compile(LOG_PATTERN)
    url_pattern = re.compile(URL_PATTERN)
    
    # Initialize metrics
    metrics = {
        'total_hits': 0,
        'content_types': Counter(),
        'categories': Counter(),
        'subcategories': Counter(),
        'urls': defaultdict(lambda: {
            'hits': 0,
            'unique_visitors': set(),
            'response_sizes': [],
            'response_times': [],
            'referrers': Counter(),
            'title': '',
            'content_type': '',
            'category': '',
            'subcategory': '',
            'last_accessed': None,
            'first_accessed': None,
        }),
        'sessions': defaultdict(list),
        'popular_content': [],
        'trending_content': [],
        'engagement_rates': {},
        'hourly_traffic': Counter(),
        'daily_traffic': Counter(),
        'search_keywords': Counter(),
        'content_engagement': defaultdict(list),
    }
    
    line_count = 0
    match_count = 0
    
    # Keep track of IP sessions (last seen timestamp)
    ip_sessions = {}
    session_timeout = datetime.timedelta(minutes=30)
    
    now = datetime.datetime.now()
    yesterday = now - datetime.timedelta(days=1)
    
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
                    response_time = match.group(9)
                    
                    # Skip bot traffic
                    if is_bot(user_agent):
                        continue
                    
                    # Parse timestamp
                    timestamp, hour, day_of_week = parse_time(time_str)
                    
                    # Extract URL from request
                    url_match = url_pattern.search(line)
                    if not url_match:
                        continue
                    
                    url = url_match.group(1)
                    
                    # Skip static resources and non-200 responses for content analysis
                    file_ext = os.path.splitext(url)[1].lower()
                    is_static = file_ext in ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg']
                    if is_static or status_code != 200:
                        continue
                    
                    # Count this hit
                    metrics['total_hits'] += 1
                    
                    # Track time patterns
                    metrics['hourly_traffic'][hour] += 1
                    metrics['daily_traffic'][day_of_week] += 1
                    
                    # Categorize content
                    content_type, category, subcategory = categorize_content(url)
                    metrics['content_types'][content_type] += 1
                    metrics['categories'][category] += 1
                    metrics['subcategories'][subcategory] += 1
                    
                    # Track URL-specific metrics
                    if url not in metrics['urls']:
                        metrics['urls'][url]['title'] = extract_title_from_url(url)
                        metrics['urls'][url]['content_type'] = content_type
                        metrics['urls'][url]['category'] = category
                        metrics['urls'][url]['subcategory'] = subcategory
                        metrics['urls'][url]['first_accessed'] = timestamp
                    
                    metrics['urls'][url]['hits'] += 1
                    metrics['urls'][url]['unique_visitors'].add(ip)
                    metrics['urls'][url]['last_accessed'] = timestamp
                    
                    if referrer != '-' and referrer != '':
                        metrics['urls'][url]['referrers'][referrer] += 1
                    
                    # Track response size
                    if response_size != '-' and response_size.isdigit():
                        size = int(response_size)
                        metrics['urls'][url]['response_sizes'].append(size)
                    
                    # Track response time
                    if response_time and response_time.replace('.', '', 1).isdigit():
                        time = float(response_time)
                        metrics['urls'][url]['response_times'].append(time)
                    
                    # Track engagement
                    if response_size != '-' and response_size.isdigit():
                        size = int(response_size)
                        reading_time = calculate_reading_time(size)
                        metrics['content_engagement'][url].append({
                            'ip': ip,
                            'timestamp': timestamp,
                            'estimated_reading_time': reading_time
                        })
                    
                    # Check if this is trending (recent popularity)
                    if timestamp > yesterday:
                        metrics['trending_content'].append((url, timestamp))
                    
                    # Session tracking
                    if ip in ip_sessions:
                        last_time = ip_sessions[ip]
                        if timestamp - last_time > session_timeout:
                            # New session
                            session_id = f"{ip}_{timestamp.timestamp()}"
                            metrics['sessions'][ip] = [(timestamp, url, session_id)]
                        else:
                            # Continue session
                            session_id = metrics['sessions'][ip][0][2]
                            metrics['sessions'][ip].append((timestamp, url, session_id))
                    else:
                        # New session
                        session_id = f"{ip}_{timestamp.timestamp()}"
                        metrics['sessions'][ip] = [(timestamp, url, session_id)]
                    
                    # Update last seen timestamp
                    ip_sessions[ip] = timestamp
        
        print(f"Processed {line_count} lines, matched {match_count} entries")
    except Exception as e:
        print(f"Error reading log file {access_log_file}: {e}")
        return None
    
    # Post-process metrics
    
    # Calculate popular content (by hits)
    for url, data in metrics['urls'].items():
        metrics['popular_content'].append((url, data['hits']))
    
    metrics['popular_content'].sort(key=lambda x: x[1], reverse=True)
    
    # Calculate trending content (recent popularity)
    trending_counts = Counter()
    for url, timestamp in metrics['trending_content']:
        trending_counts[url] += 1
    
    metrics['trending_content'] = [(url, count) for url, count in trending_counts.most_common()]
    
    # Calculate engagement metrics
    for url, engagements in metrics['content_engagement'].items():
        if not engagements:
            continue
        
        # Get URL data
        url_data = metrics['urls'][url]
        
        # Calculate average session duration for this URL
        engagement_times = []
        for session_id, session in metrics['sessions'].items():
            url_visits = [(t, u) for t, u, s in session if u == url]
            if len(url_visits) > 0:
                # If multiple visits to same URL in session, calculate time between them
                if len(url_visits) > 1:
                    for i in range(len(url_visits) - 1):
                        time_diff = (url_visits[i+1][0] - url_visits[i][0]).total_seconds()
                        if time_diff > 0 and time_diff < 3600:  # Exclude unreasonable times
                            engagement_times.append(time_diff)
                
                # Also use estimated reading time
                for e in engagements:
                    if e['ip'] == session_id.split('_')[0]:
                        engagement_times.append(e['estimated_reading_time'])
        
        # Calculate average engagement if we have data
        if engagement_times:
            avg_engagement = sum(engagement_times) / len(engagement_times)
            bounce_rate = 0
            
            # Calculate bounce rate
            url_views = 0
            url_bounces = 0
            for session_id, session in metrics['sessions'].items():
                urls_in_session = [u for t, u, s in session]
                if url in urls_in_session:
                    url_views += 1
                    if len(set(urls_in_session)) == 1:
                        url_bounces += 1
            
            if url_views > 0:
                bounce_rate = (url_bounces / url_views) * 100
            
            metrics['engagement_rates'][url] = {
                'avg_time_on_page': avg_engagement,
                'bounce_rate': bounce_rate,
                'engagement_score': avg_engagement * (1 - (bounce_rate / 100)) if bounce_rate < 100 else 0
            }
    
    return metrics

def generate_content_report(project_name, metrics, output_dir):
    """Generate an HTML report of content metrics."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"content_report_{today}.html")
    
    # Format day names
    days_of_week = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Content Report for {project_name} - {today}</title>
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
        .engagement-high {{ color: #4caf50; }}
        .engagement-medium {{ color: #ff9800; }}
        .engagement-low {{ color: #f44336; }}
        .progress-bar {{ 
            height: 10px; 
            background-color: #e0e0e0; 
            border-radius: 5px; 
            margin-top: 5px;
        }}
        .progress-fill {{ 
            height: 100%; 
            border-radius: 5px; 
            background-color: #4caf50; 
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

    <h1>Content Report for {project_name}</h1>
    <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="tabs">
        <div id="tab-overview" class="tab active" onclick="showTab('overview')">Overview</div>
        <div id="tab-popular" class="tab" onclick="showTab('popular')">Popular Content</div>
        <div id="tab-engagement" class="tab" onclick="showTab('engagement')">Content Engagement</div>
        <div id="tab-categories" class="tab" onclick="showTab('categories')">Content Categories</div>
        <div id="tab-trending" class="tab" onclick="showTab('trending')">Trending Content</div>
    </div>
    
    <div id="overview" class="tab-content active">
        <div class="metric-card">
            <h2 class="metric-title">Content Overview</h2>
            <div class="chart-container">
                <canvas id="content-types-chart"></canvas>
            </div>
            <table>
                <tr>
                    <th>Content Type</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
"""
    
    # Add content type rows
    total_content = sum(metrics['content_types'].values()) or 1  # Avoid division by zero
    for content_type, count in metrics['content_types'].most_common():
        percentage = (count / total_content) * 100
        html_content += f"""
                <tr>
                    <td>{content_type}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Content Categories</h2>
            <div class="chart-container">
                <canvas id="categories-chart"></canvas>
            </div>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Content Distribution by Time</h2>
            <div class="chart-container">
                <canvas id="hourly-content-chart"></canvas>
            </div>
        </div>
    </div>
    
    <div id="popular" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Most Popular Content</h2>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Title</th>
                    <th>Category</th>
                    <th>Views</th>
                    <th>Unique Visitors</th>
                </tr>
"""
    
    # Add popular content rows
    for url, hits in metrics['popular_content'][:30]:
        url_data = metrics['urls'][url]
        title = url_data.get('title', extract_title_from_url(url))
        category = url_data.get('category', 'Unknown')
        unique_visitors = len(url_data.get('unique_visitors', set()))
        
        html_content += f"""
                <tr>
                    <td>{url}</td>
                    <td>{title}</td>
                    <td>{category}</td>
                    <td>{hits}</td>
                    <td>{unique_visitors}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Content by Category</h2>
            <table>
                <tr>
                    <th>Category</th>
                    <th>Views</th>
                    <th>Percentage</th>
                </tr>
"""
    
    # Add category rows
    total_views = sum(metrics['categories'].values()) or 1  # Avoid division by zero
    for category, views in metrics['categories'].most_common():
        percentage = (views / total_views) * 100
        html_content += f"""
                <tr>
                    <td>{category}</td>
                    <td>{views}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
    </div>
    
    <div id="engagement" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Content Engagement Metrics</h2>
            <p>Engagement score combines time spent on page and bounce rate into a single metric.</p>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Title</th>
                    <th>Category</th>
                    <th>Avg. Time on Page</th>
                    <th>Bounce Rate</th>
                    <th>Engagement Score</th>
                </tr>
"""
    
    # Sort URLs by engagement score
    engagement_sorted = []
    for url, data in metrics['engagement_rates'].items():
        engagement_sorted.append((url, data['engagement_score']))
    
    engagement_sorted.sort(key=lambda x: x[1], reverse=True)
    
    # Add engagement rows
    for url, score in engagement_sorted[:20]:
        url_data = metrics['urls'][url]
        title = url_data.get('title', extract_title_from_url(url))
        category = url_data.get('category', 'Unknown')
        
        engagement_data = metrics['engagement_rates'][url]
        avg_time = engagement_data['avg_time_on_page']
        bounce_rate = engagement_data['bounce_rate']
        
        # Determine engagement level class
        time_class = 'engagement-low'
        if avg_time > 120:
            time_class = 'engagement-high'
        elif avg_time > 60:
            time_class = 'engagement-medium'
        
        bounce_class = 'engagement-high'
        if bounce_rate > 80:
            bounce_class = 'engagement-low'
        elif bounce_rate > 50:
            bounce_class = 'engagement-medium'
        
        score_class = 'engagement-low'
        if score > 100:
            score_class = 'engagement-high'
        elif score > 50:
            score_class = 'engagement-medium'
        
        html_content += f"""
                <tr>
                    <td>{url}</td>
                    <td>{title}</td>
                    <td>{category}</td>
                    <td class="{time_class}">{avg_time:.1f} seconds</td>
                    <td class="{bounce_class}">{bounce_rate:.1f}%</td>
                    <td class="{score_class}">{score:.1f}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Time Spent by Content Type</h2>
            <table>
                <tr>
                    <th>Content Type</th>
                    <th>Avg. Time Spent</th>
                    <th>Relative Engagement</th>
                </tr>
"""
    
    # Calculate average time spent by content type
    content_type_engagement = defaultdict(list)
    for url, data in metrics['engagement_rates'].items():
        content_type = metrics['urls'][url].get('content_type', 'Page')
        content_type_engagement[content_type].append(data['avg_time_on_page'])
    
    content_type_avg_time = {}
    for content_type, times in content_type_engagement.items():
        if times:
            content_type_avg_time[content_type] = sum(times) / len(times)
    
    # Find max average time for scaling
    max_avg_time = max(content_type_avg_time.values()) if content_type_avg_time else 1
    
    # Add content type engagement rows
    for content_type, avg_time in sorted(content_type_avg_time.items(), key=lambda x: x[1], reverse=True):
        relative_engagement = (avg_time / max_avg_time) * 100
        
        html_content += f"""
                <tr>
                    <td>{content_type}</td>
                    <td>{avg_time:.1f} seconds</td>
                    <td>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: {relative_engagement}%;"></div>
                        </div>
                    </td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
    </div>
    
    <div id="categories" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Content Performance by Category</h2>
            <table>
                <tr>
                    <th>Category</th>
                    <th>Subcategory</th>
                    <th>Views</th>
                    <th>Unique Pages</th>
                    <th>Avg. Engagement</th>
                </tr>
"""
    
    # Group URLs by category and subcategory
    category_data = defaultdict(lambda: defaultdict(list))
    for url, url_data in metrics['urls'].items():
        category = url_data.get('category', 'Unknown')
        subcategory = url_data.get('subcategory', 'Other')
        category_data[category][subcategory].append(url)
    
    # Calculate category metrics
    for category, subcategories in sorted(category_data.items()):
        for subcategory, urls in sorted(subcategories.items()):
            # Calculate total views
            total_views = sum(metrics['urls'][url]['hits'] for url in urls)
            
            # Calculate average engagement
            engagement_scores = []
            for url in urls:
                if url in metrics['engagement_rates']:
                    engagement_scores.append(metrics['engagement_rates'][url]['engagement_score'])
            
            avg_engagement = sum(engagement_scores) / len(engagement_scores) if engagement_scores else 0
            
            # Determine engagement class
            engagement_class = 'engagement-low'
            if avg_engagement > 100:
                engagement_class = 'engagement-high'
            elif avg_engagement > 50:
                engagement_class = 'engagement-medium'
            
            html_content += f"""
                <tr>
                    <td>{category}</td>
                    <td>{subcategory}</td>
                    <td>{total_views}</td>
                    <td>{len(urls)}</td>
                    <td class="{engagement_class}">{avg_engagement:.1f}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Top Content by Category</h2>
"""
    
    # For each category, show top content
    for category, count in metrics['categories'].most_common(5):
        html_content += f"""
            <h3>{category}</h3>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Title</th>
                    <th>Views</th>
                    <th>Engagement</th>
                </tr>
"""
        
        # Find top URLs in this category
        category_urls = [(url, metrics['urls'][url]['hits']) for url, data in metrics['urls'].items() 
                        if data.get('category', 'Unknown') == category]
        category_urls.sort(key=lambda x: x[1], reverse=True)
        
        for url, hits in category_urls[:5]:
            title = metrics['urls'][url].get('title', extract_title_from_url(url))
            engagement = metrics['engagement_rates'].get(url, {}).get('engagement_score', 0)
            
            engagement_class = 'engagement-low'
            if engagement > 100:
                engagement_class = 'engagement-high'
            elif engagement > 50:
                engagement_class = 'engagement-medium'
            
            html_content += f"""
                <tr>
                    <td>{url}</td>
                    <td>{title}</td>
                    <td>{hits}</td>
                    <td class="{engagement_class}">{engagement:.1f}</td>
                </tr>
"""
        
        html_content += """
            </table>
"""
    
    html_content += """
        </div>
    </div>
    
    <div id="trending" class="tab-content">
        <div class="metric-card">
            <h2 class="metric-title">Trending Content (Last 24 Hours)</h2>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Title</th>
                    <th>Category</th>
                    <th>Recent Views</th>
                    <th>Total Views</th>
                </tr>
"""
    
    # Add trending content rows
    for url, recent_views in metrics['trending_content'][:20]:
        url_data = metrics['urls'][url]
        title = url_data.get('title', extract_title_from_url(url))
        category = url_data.get('category', 'Unknown')
        total_views = url_data['hits']
        
        html_content += f"""
                <tr>
                    <td>{url}</td>
                    <td>{title}</td>
                    <td>{category}</td>
                    <td><strong>{recent_views}</strong></td>
                    <td>{total_views}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
        
        <div class="metric-card">
            <h2 class="metric-title">Content Age Analysis</h2>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Title</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                    <th>Lifespan (days)</th>
                    <th>Views</th>
                </tr>
"""
    
    # Calculate content age and lifespan
    now = datetime.datetime.now()
    for url, url_data in sorted(metrics['urls'].items(), key=lambda x: x[1].get('first_accessed', now), reverse=True)[:20]:
        title = url_data.get('title', extract_title_from_url(url))
        first_accessed = url_data.get('first_accessed')
        last_accessed = url_data.get('last_accessed')
        
        if first_accessed and last_accessed:
            first_str = first_accessed.strftime('%Y-%m-%d')
            last_str = last_accessed.strftime('%Y-%m-%d')
            lifespan = (last_accessed - first_accessed).days
            views = url_data['hits']
            
            html_content += f"""
                <tr>
                    <td>{url}</td>
                    <td>{title}</td>
                    <td>{first_str}</td>
                    <td>{last_str}</td>
                    <td>{lifespan}</td>
                    <td>{views}</td>
                </tr>
"""
    
    html_content += """
            </table>
        </div>
    </div>
    
    <script>
        // Content types chart
        const typesCtx = document.getElementById('content-types-chart').getContext('2d');
        const typesChart = new Chart(typesCtx, {
            type: 'pie',
            data: {
                labels: [
"""
    
    # Add content type labels
    for content_type, _ in metrics['content_types'].most_common():
        html_content += f"                    '{content_type}',\n"
    
    html_content += """
                ],
                datasets: [{
                    data: [
"""
    
    # Add content type counts
    for _, count in metrics['content_types'].most_common():
        html_content += f"                        {count},\n"
    
    html_content += """
                    ],
                    backgroundColor: [
                        '#4caf50',
                        '#2196f3',
                        '#ff9800',
                        '#e91e63',
                        '#9c27b0',
                        '#607d8b',
                        '#795548',
                        '#ff5722'
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
                        text: 'Content Types Distribution'
                    }
                }
            }
        });
        
        // Categories chart
        const categoriesCtx = document.getElementById('categories-chart').getContext('2d');
        const categoriesChart = new Chart(categoriesCtx, {
            type: 'doughnut',
            data: {
                labels: [
"""
    
    # Add category labels
    for category, _ in metrics['categories'].most_common(8):
        html_content += f"                    '{category}',\n"
    
    html_content += """
                ],
                datasets: [{
                    data: [
"""
    
    # Add category counts
    for _, count in metrics['categories'].most_common(8):
        html_content += f"                        {count},\n"
    
    html_content += """
                    ],
                    backgroundColor: [
                        '#4caf50',
                        '#2196f3',
                        '#ff9800',
                        '#e91e63',
                        '#9c27b0',
                        '#607d8b',
                        '#795548',
                        '#ff5722'
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
                        text: 'Content Categories'
                    }
                }
            }
        });
        
        // Hourly content chart
        const hourlyCtx = document.getElementById('hourly-content-chart').getContext('2d');
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
                    label: 'Content Views by Hour',
                    data: [
"""
    
    # Add hourly traffic data
    for hour in range(24):
        count = metrics['hourly_traffic'].get(hour, 0)
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
                            text: 'Views'
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
                        text: 'Content Consumption by Hour'
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
    """Generate a plain text report of content metrics."""
    today = datetime.datetime.now().strftime(DATE_FORMAT)
    report_file = os.path.join(output_dir, f"content_report_{today}.txt")
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f"Content Report for {project_name}\n")
        f.write("="*50 + "\n")
        f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Content overview
        f.write("CONTENT OVERVIEW\n")
        f.write("-"*50 + "\n")
        f.write(f"Total URLs analyzed: {len(metrics['urls'])}\n")
        f.write(f"Total content views: {metrics['total_hits']}\n\n")
        
        # Content types breakdown
        f.write("CONTENT TYPES\n")
        f.write("-"*50 + "\n")
        for content_type, count in metrics['content_types'].most_common():
            percentage = count / metrics['total_hits'] * 100 if metrics['total_hits'] > 0 else 0
            f.write(f"{content_type}: {count} ({percentage:.1f}%)\n")
        f.write("\n")
        
        # Popular content
        f.write("TOP 20 POPULAR CONTENT\n")
        f.write("-"*50 + "\n")
        for i, (url, hits) in enumerate(metrics['popular_content'][:20], 1):
            url_data = metrics['urls'][url]
            title = url_data.get('title', extract_title_from_url(url))
            category = url_data.get('category', 'Unknown')
            f.write(f"{i}. {title} ({category})\n")
            f.write(f"   URL: {url}\n")
            f.write(f"   Views: {hits}\n")
            
            if url in metrics['engagement_rates']:
                engagement = metrics['engagement_rates'][url]
                f.write(f"   Avg. Time on Page: {engagement['avg_time_on_page']:.1f} seconds\n")
                f.write(f"   Bounce Rate: {engagement['bounce_rate']:.1f}%\n")
            
            f.write("\n")
        
        # Trending content
        f.write("TOP 10 TRENDING CONTENT (LAST 24 HOURS)\n")
        f.write("-"*50 + "\n")
        for i, (url, recent_views) in enumerate(metrics['trending_content'][:10], 1):
            url_data = metrics['urls'][url]
            title = url_data.get('title', extract_title_from_url(url))
            total_views = url_data['hits']
            f.write(f"{i}. {title}\n")
            f.write(f"   URL: {url}\n")
            f.write(f"   Recent Views: {recent_views}\n")
            f.write(f"   Total Views: {total_views}\n\n")
        
        # Categories
        f.write("CONTENT CATEGORIES\n")
        f.write("-"*50 + "\n")
        for category, views in metrics['categories'].most_common():
            percentage = views / metrics['total_hits'] * 100 if metrics['total_hits'] > 0 else 0
            f.write(f"{category}: {views} views ({percentage:.1f}%)\n")
    
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
        html_report_file = generate_content_report(project_name, metrics, date_dir)
        print(f"Generated HTML content report for {project_name}: {html_report_file}")
        
        # Generate plain text report
        text_report_file = generate_plain_text_report(project_name, metrics, date_dir)
        print(f"Generated text content report for {project_name}: {text_report_file}")
        
        # Create copies in the project directory for the summary
        html_report_basename = os.path.basename(html_report_file)
        text_report_basename = os.path.basename(text_report_file)
        shutil.copy(html_report_file, os.path.join(project_dir, html_report_basename))
        shutil.copy(text_report_file, os.path.join(project_dir, text_report_basename))
    
    print("Content analysis completed successfully.")

if __name__ == "__main__":
    main()
