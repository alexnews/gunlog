#!/usr/bin/env python3
"""
GunLog Master Analytics Runner

This script runs all GunLog analytics modules in sequence and generates a
complete set of analytics reports for your web projects.

Usage:
    python gunlog_master.py

Requirements:
    - All GunLog analytics scripts in the same directory
    - Configuration file (config.py) with path settings
"""

import os
import sys
import time
import subprocess
import datetime

def run_script(script_name, description):
    """
    Run a Python script and log the result.
    
    Args:
        script_name: Name of the script file to run
        description: Description of what the script does
    
    Returns:
        bool: True if the script ran successfully, False otherwise
    """
    print("\n" + "="*80)
    print(f"Running: {script_name} - {description}")
    print("="*80)
    
    start_time = time.time()
    
    try:
        # Check if the script exists
        if not os.path.exists(script_name):
            print(f"ERROR: Script {script_name} not found!")
            return False
        
        # Run the script
        result = subprocess.run([sys.executable, script_name], capture_output=True, text=True)
        
        # Check the result
        if result.returncode == 0:
            print(f"SUCCESS: {script_name} completed successfully")
            print(f"Output: {result.stdout[:500]}..." if len(result.stdout) > 500 else f"Output: {result.stdout}")
            elapsed_time = time.time() - start_time
            print(f"Time taken: {elapsed_time:.2f} seconds")
            return True
        else:
            print(f"ERROR: {script_name} failed with return code {result.returncode}")
            print(f"Error output: {result.stderr}")
            return False
    
    except Exception as e:
        print(f"ERROR: Failed to run {script_name} - {str(e)}")
        return False

def main():
    """Main function to run all analytics scripts."""
    print("GunLog Master Analytics Runner")
    print("-"*50)
    print(f"Started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Running from directory: {os.getcwd()}")
    print("-"*50)
    
    # Define all scripts to run and their descriptions
    scripts = [
        {"name": "gunlog_error.py", "description": "Error Analytics - Analyzing PHP errors and warnings"},
        {"name": "gunlog_ip2.py", "description": "IP Analytics - Analyzing visitor IP addresses and locations"},
        {"name": "gunlog_popular.py", "description": "Page Analytics - Analyzing most viewed pages"},
        {"name": "gunlog_performance.py", "description": "Performance Analytics - Analyzing website performance metrics"},
        {"name": "gunlog_content.py", "description": "Content Analytics - Analyzing content engagement metrics"},
        {"name": "gunlog_security.py", "description": "Security Analytics - Analyzing security events and threats"},
        {"name": "gunlog_seo.py", "description": "SEO Analytics - Analyzing search engine optimization metrics"},
        {"name": "gunlog_traffic.py", "description": "Traffic Analytics - Analyzing visitor traffic patterns"},
        {"name": "gunlog_daily_summary.py", "description": "Daily Summary - Generating daily error and access summaries"},
        {"name": "gunlog_index_generator.py", "description": "Index Generator - Creating unified dashboard index pages"}
    ]
    
    # Run each script
    results = []
    for script in scripts:
        success = run_script(script["name"], script["description"])
        results.append({
            "script": script["name"],
            "success": success,
            "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    
    # Print summary
    print("\n" + "="*80)
    print("ANALYTICS RUN SUMMARY")
    print("="*80)
    
    successful = sum(1 for r in results if r["success"])
    failed = len(results) - successful
    
    print(f"Total scripts: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print("\nDetailed results:")
    print("-"*50)
    
    for result in results:
        status = "SUCCESS" if result["success"] else "FAILED"
        print(f"{result['script']}: {status} at {result['timestamp']}")
    
    print("-"*50)
    print(f"Analytics run completed at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Return success status for the entire run
    return failed == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
