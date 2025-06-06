#!/usr/bin/env python3
"""
Comprehensive test script for CLI Network Scanner
Tests all features to ensure they work as intended
"""

import subprocess
import sys
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def run_command(cmd, timeout=30):
    """Run a command and return success status and output"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding='utf-8',
            errors='replace'  # Replace problematic characters
        )
        return result.returncode == 0, result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)

def test_feature(name, command, expected_keywords=None):
    """Test a specific feature"""
    console.print(f"\n[bold cyan]Testing {name}...[/bold cyan]")
    
    success, stdout, stderr = run_command(command)
    
    if success:
        # Check for expected keywords in output
        if expected_keywords and stdout:
            found_keywords = []
            for keyword in expected_keywords:
                if keyword.lower() in stdout.lower():
                    found_keywords.append(keyword)
            
            if len(found_keywords) == len(expected_keywords):
                console.print(f"[green]✓ {name} - PASSED[/green]")
                return True
            else:
                missing = set(expected_keywords) - set(found_keywords)
                console.print(f"[yellow]⚠ {name} - PARTIAL (missing: {missing})[/yellow]")
                return False
        else:
            console.print(f"[green]✓ {name} - PASSED[/green]")
            return True
    else:
        console.print(f"[red]✗ {name} - FAILED[/red]")
        if stderr:
            console.print(f"[red]Error: {stderr}[/red]")
        return False

def main():
    """Run all feature tests"""
    console.print(Panel(
        "[bold]CLI Network Scanner - Comprehensive Feature Test[/bold]\n"
        "Testing all features to ensure they work as intended",
        title="Feature Testing",
        border_style="blue"
    ))
    
    # Test cases: (name, command, expected_keywords)
    tests = [
        # Basic help and version
        ("Help Command", "python networkscanner.py --help", ["usage", "NetworkScan Pro"]),
        
        # Port Scanner
        ("Port Scanner - Basic", "python networkscanner.py scan google.com --ports 80,443", 
         ["Scan Results", "open", "google.com"]),
        
        # Ping Utility
        ("Ping Utility", "python networkscanner.py ping google.com --count 2", 
         ["Ping Results", "Packets Sent", "reachable"]),
        
        # Traceroute
        ("Traceroute", "python networkscanner.py trace google.com --max-hops 5", 
         ["Traceroute Results", "Hop", "google.com"]),
        
        # DNS Tools
        ("DNS A Record Lookup", "python networkscanner.py dns google.com --type a", 
         ["A Record Lookup Results", "IP Address"]),
        
        ("DNS MX Record Lookup", "python networkscanner.py dns google.com --type mx", 
         ["MX Record Lookup Results", "Mail Server"]),
        
        # Network Info
        ("Network Info - Local", "python networkscanner.py netinfo --type local", 
         ["Network Interfaces", "Hostname"]),
        
        ("Network Info - Public", "python networkscanner.py netinfo --type public",
         ["Public IP", "retrieved"]),
        
        # SSL Certificate Checker
        ("SSL Certificate Checker", "python networkscanner.py ssl google.com", 
         ["Certificate Details", "Valid", "Subject"]),
        
        # IP Geolocation
        ("IP Geolocation", "python networkscanner.py geoip 8.8.8.8", 
         ["Geolocation Information", "Country", "Google"]),
        
        # Device Discovery (quick test with small range)
        ("Device Discovery", "python networkscanner.py discover --network 127.0.0.0/30 --threads 5", 
         ["device discovery", "Scanning"]),
    ]
    
    # Run tests
    passed = 0
    total = len(tests)
    
    for name, command, keywords in tests:
        if test_feature(name, command, keywords):
            passed += 1
        time.sleep(1)  # Brief pause between tests
    
    # Summary
    console.print(f"\n[bold]Test Summary:[/bold]")
    console.print(f"Passed: [green]{passed}[/green]")
    console.print(f"Failed: [red]{total - passed}[/red]")
    console.print(f"Total: {total}")
    
    if passed == total:
        console.print(f"\n[bold green]🎉 All tests passed! The CLI Network Scanner is working perfectly.[/bold green]")
    else:
        console.print(f"\n[bold yellow]⚠ {total - passed} test(s) failed. Some features may need attention.[/bold yellow]")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
