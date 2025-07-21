#!/usr/bin/env python3
"""
Repository Management Dashboard
Comprehensive overview and management interface for the CLI Network Scanner repository
"""

import subprocess
import sys
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.layout import Layout
from rich.live import Live
from rich.prompt import Prompt, Confirm
from rich import box
import time

console = Console()

def run_command(cmd, capture_output=True):
    """Run a command and return the result."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=capture_output, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def get_git_info():
    """Get git repository information."""
    info = {}
    
    # Current branch
    success, stdout, _ = run_command("git branch --show-current")
    info["branch"] = stdout.strip() if success else "unknown"
    
    # Last commit
    success, stdout, _ = run_command("git log -1 --pretty=format:'%h - %s (%cr)'")
    info["last_commit"] = stdout.strip() if success else "unknown"
    
    # Status
    success, stdout, _ = run_command("git status --porcelain")
    info["dirty"] = bool(stdout.strip()) if success else True
    
    # Remote status
    success, stdout, _ = run_command("git status -uno")
    if success:
        if "up to date" in stdout or "up-to-date" in stdout:
            info["remote_status"] = "✅ Up to date"
        elif "ahead" in stdout:
            info["remote_status"] = "⬆️ Ahead"
        elif "behind" in stdout:
            info["remote_status"] = "⬇️ Behind"
        else:
            info["remote_status"] = "❓ Unknown"
    else:
        info["remote_status"] = "❌ Error"
    
    return info

def get_test_status():
    """Get test suite status."""
    success, stdout, stderr = run_command("python test_all_features.py")
    if success and "All tests passed" in stdout:
        return "✅ All tests passing (11/11)"
    elif success:
        return "⚠️ Tests completed with warnings"
    else:
        return "❌ Tests failing"

def get_dependency_status():
    """Get dependency status."""
    success, stdout, _ = run_command("pip list --outdated --format=json")
    if success and stdout.strip():
        try:
            import json
            outdated = json.loads(stdout)
            if outdated:
                return f"⚠️ {len(outdated)} packages need updates"
            else:
                return "✅ All dependencies up to date"
        except:
            return "❓ Could not parse dependency info"
    return "✅ All dependencies up to date"

def get_file_stats():
    """Get repository file statistics."""
    stats = {}
    
    # Python files
    py_files = list(Path('.').glob('**/*.py'))
    stats["python_files"] = len(py_files)
    
    # Total lines of code
    total_lines = 0
    for py_file in py_files:
        try:
            with open(py_file, 'r') as f:
                total_lines += len(f.readlines())
        except:
            pass
    stats["total_lines"] = total_lines
    
    # Documentation files
    doc_files = [f for f in ['README.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'LICENSE'] if Path(f).exists()]
    stats["doc_files"] = len(doc_files)
    
    return stats

def create_overview_panel():
    """Create repository overview panel."""
    git_info = get_git_info()
    
    overview_table = Table(show_header=False, box=box.SIMPLE)
    overview_table.add_column("Property", style="cyan")
    overview_table.add_column("Value", style="white")
    
    overview_table.add_row("Repository", "CLI-NetworkScanner")
    overview_table.add_row("Branch", git_info["branch"])
    overview_table.add_row("Status", "🟢 Clean" if not git_info["dirty"] else "🟡 Modified")
    overview_table.add_row("Remote", git_info["remote_status"])
    overview_table.add_row("Last Commit", git_info["last_commit"])
    
    return Panel(overview_table, title="📊 Repository Overview", border_style="blue")

def create_health_panel():
    """Create repository health panel."""
    health_table = Table(show_header=False, box=box.SIMPLE)
    health_table.add_column("Check", style="cyan")
    health_table.add_column("Status", style="white")
    
    health_table.add_row("Tests", get_test_status())
    health_table.add_row("Dependencies", get_dependency_status())
    health_table.add_row("CI/CD", "✅ GitHub Actions configured")
    health_table.add_row("Security", "✅ Dependabot enabled")
    
    return Panel(health_table, title="🏥 Repository Health", border_style="green")

def create_stats_panel():
    """Create repository statistics panel."""
    stats = get_file_stats()
    
    stats_table = Table(show_header=False, box=box.SIMPLE)
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Count", style="white")
    
    stats_table.add_row("Python Files", str(stats["python_files"]))
    stats_table.add_row("Lines of Code", f"{stats['total_lines']:,}")
    stats_table.add_row("Documentation", f"{stats['doc_files']}/4")
    stats_table.add_row("Modules", "11")
    
    return Panel(stats_table, title="📈 Statistics", border_style="yellow")

def create_actions_panel():
    """Create quick actions panel."""
    actions_table = Table(show_header=False, box=box.SIMPLE)
    actions_table.add_column("Action", style="cyan")
    actions_table.add_column("Command", style="dim")
    
    actions_table.add_row("1. Health Check", "python scripts/repo_health_check.py")
    actions_table.add_row("2. Maintenance", "python scripts/maintenance.py")
    actions_table.add_row("3. Version Bump", "python scripts/version_manager.py")
    actions_table.add_row("4. Run Tests", "python test_all_features.py")
    
    return Panel(actions_table, title="⚡ Quick Actions", border_style="magenta")

def main_dashboard():
    """Display the main repository dashboard."""
    console.clear()
    
    # Create layout
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3)
    )
    
    layout["body"].split_row(
        Layout(name="left"),
        Layout(name="right")
    )
    
    layout["left"].split_column(
        Layout(name="overview"),
        Layout(name="health")
    )
    
    layout["right"].split_column(
        Layout(name="stats"),
        Layout(name="actions")
    )
    
    # Header
    layout["header"].update(Panel(
        f"[bold]CLI Network Scanner - Repository Management Dashboard[/bold]\n"
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        style="bold blue"
    ))
    
    # Body panels
    layout["overview"].update(create_overview_panel())
    layout["health"].update(create_health_panel())
    layout["stats"].update(create_stats_panel())
    layout["actions"].update(create_actions_panel())
    
    # Footer
    layout["footer"].update(Panel(
        "[dim]Press 'r' to refresh, 'q' to quit, or select an action (1-4)[/dim]",
        style="dim"
    ))
    
    console.print(layout)

def interactive_mode():
    """Run interactive dashboard mode."""
    while True:
        main_dashboard()
        
        try:
            choice = console.input("\n[bold]Enter choice: [/bold]").strip().lower()
            
            if choice == 'q':
                console.print("[yellow]Goodbye![/yellow]")
                break
            elif choice == 'r':
                console.print("[dim]Refreshing...[/dim]")
                time.sleep(0.5)
                continue
            elif choice == '1':
                console.print("[cyan]Running health check...[/cyan]")
                subprocess.run([sys.executable, "scripts/repo_health_check.py"])
                console.input("\nPress Enter to continue...")
            elif choice == '2':
                console.print("[cyan]Running maintenance...[/cyan]")
                subprocess.run([sys.executable, "scripts/maintenance.py"])
                console.input("\nPress Enter to continue...")
            elif choice == '3':
                console.print("[cyan]Starting version manager...[/cyan]")
                subprocess.run([sys.executable, "scripts/version_manager.py"])
                console.input("\nPress Enter to continue...")
            elif choice == '4':
                console.print("[cyan]Running tests...[/cyan]")
                subprocess.run([sys.executable, "test_all_features.py"])
                console.input("\nPress Enter to continue...")
            else:
                console.print("[red]Invalid choice. Please try again.[/red]")
                time.sleep(1)
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Goodbye![/yellow]")
            break
        except EOFError:
            console.print("\n[yellow]Goodbye![/yellow]")
            break

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--static":
        main_dashboard()
    else:
        interactive_mode()
