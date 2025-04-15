# GunLog 🔍

A comprehensive web server log analysis toolkit for Apache2/Nginx web administrators.

**Created by: Alex Kargin**
**Ver: 1.00 - 2025/04/15**

## Overview

GunLog is a powerful Python-based toolkit designed to help web administrators gain actionable insights from their server logs. It parses and analyzes Apache2/Nginx access and error logs to generate comprehensive HTML and text reports covering various aspects of web server performance, security, traffic patterns, and SEO metrics.

## Features

- **Error Analysis**: Identify and track PHP errors, warnings, and notices
- **IP Analytics**: Track visitor IPs with optional geolocation lookup
- **Performance Monitoring**: Analyze response times, HTTP status codes, and page load metrics
- **Security Analysis**: Detect potential threats, suspicious IPs, and attack patterns
- **SEO Insights**: Monitor search engine bot activity, organic keywords, and crawl patterns
- **Content Analysis**: Track most popular pages, engagement metrics, and content performance
- **Traffic Patterns**: Visualize visitor behavior, referrer sources, and session flows
- **Daily Summaries**: Generate daily error counts and traffic summaries

## Installation

1. Clone this repository
2. Install required dependencies:
   ```
   pip install requests user-agents geoip2
   ```
3. Configure your web projects in `list_projects.csv`
4. Configure output paths in `config.py`

## Usage

Run the master script to generate all reports:

```
python gunlog.py
```

Or run individual modules for specific analyses:

```
python3 gunlog_error.py: "Error Analytics - Analyzing PHP errors and warnings",
python3 gunlog_ip2.py: "IP Analytics - Analyzing visitor IP addresses and locations",
python3 gunlog_popular.py: "Page Analytics - Analyzing most viewed pages",
python3 gunlog_performance.py: "Performance Analytics - Analyzing website performance metrics",
python3 gunlog_content.py: "Content Analytics - Analyzing content engagement metrics",
python3 gunlog_security.py: "Security Analytics - Analyzing security events and threats",
python3 gunlog_seo.py: "SEO Analytics - Analyzing search engine optimization metrics",
python3 gunlog_traffic.py: "Traffic Analytics - Analyzing visitor traffic patterns",
python3 gunlog_daily_summary.py: "Daily Summary - Generating daily error and access summaries",
python3 gunlog_index_generator.py: "Index Generator - Creating unified dashboard index pages"
...
```
python3 gunlog_ip.py: "IP Analytics - Visitor IP addresses with out any location",

## Output

GunLog generates HTML reports with interactive charts and text reports for each analysis type. Reports are organized by:
- Project
- Date
- Analysis type

A central dashboard is created to provide easy navigation between all reports.

## Configuration

Edit `config.py` to set:
- Output directory paths
- Date formatting
- Error patterns
- CSV file location

Define your web projects in `list_projects.csv` with columns:
- project: website domain
- log_file: path to access log
- error_log_file: path to error log

## Requirements

- Python 3.6+
- Apache2/Nginx web server logs
- Optional: GeoIP database for IP geolocation

## License

[MIT License](LICENSE)

## Author

**[Your Name]**
- GitHub: [@alexnews](https://github.com/alexnews)
- LinkedIn: (https://linkedin.com/in/kargin)

## Contributing

Contributions welcome! Please feel free to submit a Pull Request.