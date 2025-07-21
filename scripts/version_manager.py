#!/usr/bin/env python3
"""
Version Management Script for CLI Network Scanner
Handles version bumping, changelog updates, and release preparation
"""

import re
import sys
import subprocess
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

console = Console()

def get_current_version():
    """Get current version from networkscanner.py."""
    try:
        with open('networkscanner.py', 'r') as f:
            content = f.read()
            match = re.search(r'VERSION = ["\']([^"\']+)["\']', content)
            if match:
                return match.group(1)
    except FileNotFoundError:
        pass
    return None

def update_version_in_file(file_path, old_version, new_version):
    """Update version in a specific file."""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Replace version string
        content = re.sub(
            rf'VERSION = ["\']({re.escape(old_version)})["\']',
            f'VERSION = "{new_version}"',
            content
        )
        
        with open(file_path, 'w') as f:
            f.write(content)
        
        return True
    except Exception as e:
        console.print(f"[red]Error updating {file_path}: {e}[/red]")
        return False

def bump_version(current_version, bump_type):
    """Bump version based on type (major, minor, patch)."""
    try:
        parts = current_version.split('.')
        major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
        
        if bump_type == 'major':
            major += 1
            minor = 0
            patch = 0
        elif bump_type == 'minor':
            minor += 1
            patch = 0
        elif bump_type == 'patch':
            patch += 1
        else:
            raise ValueError(f"Invalid bump type: {bump_type}")
        
        return f"{major}.{minor}.{patch}"
    except Exception as e:
        console.print(f"[red]Error bumping version: {e}[/red]")
        return None

def update_changelog(version, changes):
    """Update CHANGELOG.md with new version."""
    try:
        changelog_path = Path('CHANGELOG.md')
        if not changelog_path.exists():
            console.print("[red]CHANGELOG.md not found[/red]")
            return False
        
        with open(changelog_path, 'r') as f:
            content = f.read()
        
        # Find the [Unreleased] section and add new version
        today = datetime.now().strftime('%Y-%m-%d')
        new_entry = f"""## [{version}] - {today}

{changes}

## [Unreleased]

"""
        
        # Replace [Unreleased] section
        content = re.sub(
            r'## \[Unreleased\]\s*\n',
            new_entry,
            content,
            count=1
        )
        
        with open(changelog_path, 'w') as f:
            f.write(content)
        
        return True
    except Exception as e:
        console.print(f"[red]Error updating changelog: {e}[/red]")
        return False

def run_tests():
    """Run the test suite."""
    console.print("[dim]Running test suite...[/dim]")
    try:
        result = subprocess.run(['python', 'test_all_features.py'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            console.print("[green]✓ All tests passed[/green]")
            return True
        else:
            console.print(f"[red]✗ Tests failed: {result.stderr}[/red]")
            return False
    except Exception as e:
        console.print(f"[red]Error running tests: {e}[/red]")
        return False

def git_commit_and_tag(version, message):
    """Commit changes and create git tag."""
    try:
        # Add files
        subprocess.run(['git', 'add', 'networkscanner.py', 'CHANGELOG.md'], check=True)
        
        # Commit
        subprocess.run(['git', 'commit', '-m', message], check=True)
        
        # Create tag
        tag_name = f"v{version}"
        subprocess.run(['git', 'tag', '-a', tag_name, '-m', f"Release {version}"], check=True)
        
        console.print(f"[green]✓ Created commit and tag {tag_name}[/green]")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Git error: {e}[/red]")
        return False

def main():
    """Main version management function."""
    console.print(Panel(
        "[bold]CLI Network Scanner - Version Manager[/bold]\n"
        "Manage versions, changelog, and releases",
        title="Version Management",
        border_style="blue"
    ))
    
    # Get current version
    current_version = get_current_version()
    if not current_version:
        console.print("[red]Could not find current version in networkscanner.py[/red]")
        return
    
    console.print(f"[cyan]Current version: {current_version}[/cyan]")
    
    # Get bump type
    bump_type = Prompt.ask(
        "Version bump type",
        choices=["major", "minor", "patch"],
        default="patch"
    )
    
    # Calculate new version
    new_version = bump_version(current_version, bump_type)
    if not new_version:
        return
    
    console.print(f"[green]New version: {new_version}[/green]")
    
    # Get changelog entry
    console.print("\n[bold]Enter changelog for this version:[/bold]")
    console.print("[dim]Enter changes, one per line. Press Ctrl+D (Unix) or Ctrl+Z (Windows) when done.[/dim]")
    
    changes_lines = []
    try:
        while True:
            line = input("• ")
            if line.strip():
                changes_lines.append(f"- {line.strip()}")
    except EOFError:
        pass
    
    if not changes_lines:
        changes_lines = [f"- Version {new_version} release"]
    
    changes = "\n".join(changes_lines)
    
    # Confirm changes
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"Version: {current_version} → {new_version}")
    console.print(f"Changes:\n{changes}")
    
    if not Confirm.ask("\nProceed with version update?"):
        console.print("[yellow]Version update cancelled[/yellow]")
        return
    
    # Run tests first
    if not run_tests():
        if not Confirm.ask("Tests failed. Continue anyway?"):
            return
    
    # Update version in files
    if not update_version_in_file('networkscanner.py', current_version, new_version):
        return
    
    # Update changelog
    if not update_changelog(new_version, changes):
        return
    
    # Git commit and tag
    commit_message = f"Release v{new_version}\n\n{changes}"
    if git_commit_and_tag(new_version, commit_message):
        console.print(f"\n[bold green]🎉 Version {new_version} ready![/bold green]")
        console.print("\n[bold]Next steps:[/bold]")
        console.print("1. Review the changes")
        console.print("2. Push to GitHub: git push origin main --tags")
        console.print("3. GitHub Actions will create the release automatically")
    else:
        console.print("[red]Failed to create git commit and tag[/red]")

if __name__ == "__main__":
    main()
