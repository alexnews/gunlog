#!/usr/bin/env python3
"""
GunLog Configuration

This file contains configuration settings for the GunLog error analyzer.
Edit this file to change paths and other settings.
"""

# File and directory paths
PROJECTS_CSV = "list_projects.csv"
OUTPUT_BASE_DIR = "/usr/local/www/example.com/www/gunlog/"

# Date format used for directory names and reports
DATE_FORMAT = "%Y%m%d"

# Error log regex pattern
ERROR_PATTERN = r'PHP (?:Warning|Notice|Error|Fatal error|Parse error):\s+(.*?) in (.*?) on line (\d+)'
