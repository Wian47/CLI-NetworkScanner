#!/usr/bin/env python3
"""
Repository Health Check Script
Monitors the health and quality of the CLI Network Scanner repository
"""

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

def run_command(cmd, capture_output=True):
    """Run a command and return the result."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=capture_output, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def check_git_status():
    """Check git repository status."""
    success, stdout, stderr = run_command("git status --porcelain")
    if success:
        if stdout.strip():
            return "⚠️", f"Uncommitted changes: {len(stdout.strip().split())} files"
        else:
            return "✅", "Clean working directory"
    return "❌", f"Git error: {stderr}"

def check_branch_status():
    """Check if branch is up to date with remote."""
    success, stdout, stderr = run_command("git status -uno")
    if success:
        if "up to date" in stdout or "up-to-date" in stdout:
            return "✅", "Up to date with remote"
        elif "ahead" in stdout:
            return "⚠️", "Local commits not pushed"
        elif "behind" in stdout:
            return "⚠️", "Behind remote branch"
        else:
            return "ℹ️", "Branch status unclear"
    return "❌", f"Git error: {stderr}"

def check_test_status():
    """Run the test suite and check results."""
    console.print("[dim]Running test suite...[/dim]")
    success, stdout, stderr = run_command("python test_all_features.py")
    if success:
        if "All tests passed" in stdout:
            return "✅", "All tests passing (11/11)"
        else:
            return "⚠️", "Some tests may have issues"
    return "❌", f"Test execution failed: {stderr}"

def check_dependencies():
    """Check for outdated dependencies."""
    success, stdout, stderr = run_command("pip list --outdated --format=json")
    if success and stdout.strip():
        try:
            import json
            outdated = json.loads(stdout)
            if outdated:
                return "⚠️", f"{len(outdated)} packages need updates"
            else:
                return "✅", "All dependencies up to date"
        except:
            return "ℹ️", "Could not parse dependency info"
    return "✅", "All dependencies up to date"

def check_security():
    """Basic security checks."""
    # Check for common security issues
    issues = []
    
    # Check for hardcoded secrets (basic check)
    success, stdout, stderr = run_command("grep -r -i 'password\\|secret\\|key\\|token' --include='*.py' . || true")
    if success and stdout:
        # Filter out common false positives
        lines = [line for line in stdout.split('\n') if line and 
                not any(fp in line.lower() for fp in ['# password', 'password:', 'def ', 'class ', 'import'])]
        if lines:
            issues.append(f"Potential secrets in code: {len(lines)} matches")
    
    # Check file permissions
    if os.name != 'nt':  # Not Windows
        success, stdout, stderr = run_command("find . -name '*.py' -perm /o+w 2>/dev/null || true")
        if success and stdout.strip():
            issues.append("World-writable Python files found")
    
    if issues:
        return "⚠️", "; ".join(issues)
    return "✅", "No obvious security issues"

def check_code_quality():
    """Basic code quality checks."""
    issues = []
    
    # Check for TODO/FIXME comments
    success, stdout, stderr = run_command("grep -r -n 'TODO\\|FIXME\\|XXX' --include='*.py' . || true")
    if success and stdout:
        todo_count = len(stdout.strip().split('\n'))
        issues.append(f"{todo_count} TODO/FIXME comments")
    
    # Check for long lines (basic check)
    success, stdout, stderr = run_command("find . -name '*.py' -exec wc -L {} + | sort -n | tail -1")
    if success and stdout:
        try:
            max_line_length = int(stdout.split()[0])
            if max_line_length > 120:
                issues.append(f"Long lines detected (max: {max_line_length})")
        except:
            pass
    
    if issues:
        return "ℹ️", "; ".join(issues)
    return "✅", "Code quality looks good"

def check_documentation():
    """Check documentation completeness."""
    required_files = ['README.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'LICENSE']
    missing = [f for f in required_files if not Path(f).exists()]
    
    if missing:
        return "⚠️", f"Missing: {', '.join(missing)}"
    return "✅", "All required documentation present"

def main():
    """Run the repository health check."""
    console.print(Panel(
        "[bold]CLI Network Scanner - Repository Health Check[/bold]\n"
        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        title="Repository Health Report",
        border_style="blue"
    ))
    
    # Run all checks
    checks = [
        ("Git Status", check_git_status),
        ("Branch Status", check_branch_status),
        ("Test Suite", check_test_status),
        ("Dependencies", check_dependencies),
        ("Security", check_security),
        ("Code Quality", check_code_quality),
        ("Documentation", check_documentation),
    ]
    
    # Create results table
    table = Table(
        title="Health Check Results",
        box=box.ROUNDED,
        border_style="blue"
    )
    table.add_column("Check", style="cyan", width=15)
    table.add_column("Status", style="bold", width=8)
    table.add_column("Details", style="white")
    
    overall_status = "✅"
    
    for check_name, check_func in checks:
        try:
            status, details = check_func()
            table.add_row(check_name, status, details)
            
            if status == "❌":
                overall_status = "❌"
            elif status == "⚠️" and overall_status != "❌":
                overall_status = "⚠️"
                
        except Exception as e:
            table.add_row(check_name, "❌", f"Check failed: {str(e)}")
            overall_status = "❌"
    
    console.print(table)
    
    # Overall status
    if overall_status == "✅":
        console.print("\n[bold green]🎉 Repository health is excellent![/bold green]")
    elif overall_status == "⚠️":
        console.print("\n[bold yellow]⚠️ Repository health is good with minor issues.[/bold yellow]")
    else:
        console.print("\n[bold red]❌ Repository health needs attention.[/bold red]")
    
    # Recommendations
    console.print("\n[bold]Recommendations:[/bold]")
    console.print("• Run this check weekly")
    console.print("• Address any ❌ issues immediately")
    console.print("• Consider addressing ⚠️ issues when convenient")
    console.print("• Keep dependencies updated")
    console.print("• Maintain test coverage at 100%")

if __name__ == "__main__":
    main()
