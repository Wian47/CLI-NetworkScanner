#!/usr/bin/env python3
"""
Repository Maintenance Script
Performs routine maintenance tasks for the CLI Network Scanner repository
"""

import os
import subprocess
import shutil
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.prompt import Confirm

console = Console()

def run_command(cmd, capture_output=True):
    """Run a command and return the result."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=capture_output, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def clean_cache_files():
    """Remove Python cache files and directories."""
    cache_patterns = [
        "**/__pycache__",
        "**/*.pyc",
        "**/*.pyo",
        "**/*.pyd",
        "**/.pytest_cache",
        "**/.*_cache"
    ]
    
    removed_count = 0
    
    for pattern in cache_patterns:
        for path in Path('.').glob(pattern):
            try:
                if path.is_file():
                    path.unlink()
                    removed_count += 1
                elif path.is_dir():
                    shutil.rmtree(path)
                    removed_count += 1
            except Exception as e:
                console.print(f"[yellow]Warning: Could not remove {path}: {e}[/yellow]")
    
    return removed_count

def clean_temp_files():
    """Remove temporary files."""
    temp_patterns = [
        "**/*.tmp",
        "**/*.temp",
        "**/*~",
        "**/.DS_Store",
        "**/Thumbs.db",
        "**/*.swp",
        "**/*.swo"
    ]
    
    removed_count = 0
    
    for pattern in temp_patterns:
        for path in Path('.').glob(pattern):
            try:
                if path.is_file():
                    path.unlink()
                    removed_count += 1
            except Exception as e:
                console.print(f"[yellow]Warning: Could not remove {path}: {e}[/yellow]")
    
    return removed_count

def update_gitignore():
    """Ensure .gitignore is comprehensive."""
    gitignore_additions = [
        "# IDE files",
        ".vscode/",
        ".idea/",
        "*.swp",
        "*.swo",
        "",
        "# OS files", 
        ".DS_Store",
        "Thumbs.db",
        "",
        "# Temporary files",
        "*.tmp",
        "*.temp",
        "*~",
        "",
        "# Test coverage",
        ".coverage",
        "htmlcov/",
        "",
        "# Distribution",
        "dist/",
        "*.egg-info/",
    ]
    
    gitignore_path = Path('.gitignore')
    if gitignore_path.exists():
        with open(gitignore_path, 'r') as f:
            current_content = f.read()
        
        additions_needed = []
        for line in gitignore_additions:
            if line and line not in current_content:
                additions_needed.append(line)
        
        if additions_needed:
            with open(gitignore_path, 'a') as f:
                f.write('\n' + '\n'.join(additions_needed))
            return len(additions_needed)
    
    return 0

def check_file_permissions():
    """Check and fix file permissions (Unix-like systems only)."""
    if os.name == 'nt':  # Windows
        return 0
    
    fixed_count = 0
    
    # Make Python files executable if they have shebang
    for py_file in Path('.').glob('**/*.py'):
        try:
            with open(py_file, 'r') as f:
                first_line = f.readline()
            
            if first_line.startswith('#!'):
                # Should be executable
                current_mode = py_file.stat().st_mode
                if not (current_mode & 0o111):  # Not executable
                    py_file.chmod(current_mode | 0o755)
                    fixed_count += 1
        except Exception:
            pass
    
    return fixed_count

def optimize_repository():
    """Run git maintenance commands."""
    commands = [
        ("git gc --aggressive", "Garbage collection"),
        ("git prune", "Prune unreachable objects"),
        ("git remote prune origin", "Prune remote branches")
    ]
    
    success_count = 0
    
    for cmd, description in commands:
        success, stdout, stderr = run_command(cmd)
        if success:
            success_count += 1
        else:
            console.print(f"[yellow]Warning: {description} failed: {stderr}[/yellow]")
    
    return success_count

def validate_project_structure():
    """Validate that all required files and directories exist."""
    required_files = [
        'README.md',
        'requirements.txt',
        'networkscanner.py',
        'test_all_features.py',
        'CHANGELOG.md',
        'CONTRIBUTING.md',
        'LICENSE'
    ]
    
    required_dirs = [
        'modules',
        'data',
        'reports',
        '.github'
    ]
    
    missing_files = [f for f in required_files if not Path(f).exists()]
    missing_dirs = [d for d in required_dirs if not Path(d).exists()]
    
    return missing_files, missing_dirs

def main():
    """Run repository maintenance."""
    console.print(Panel(
        "[bold]CLI Network Scanner - Repository Maintenance[/bold]\n"
        "Performing routine maintenance tasks",
        title="Repository Maintenance",
        border_style="green"
    ))
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        # Clean cache files
        task = progress.add_task("Cleaning cache files...", total=None)
        cache_removed = clean_cache_files()
        progress.update(task, description=f"✓ Cleaned {cache_removed} cache files")
        
        # Clean temporary files
        task = progress.add_task("Cleaning temporary files...", total=None)
        temp_removed = clean_temp_files()
        progress.update(task, description=f"✓ Cleaned {temp_removed} temporary files")
        
        # Update .gitignore
        task = progress.add_task("Updating .gitignore...", total=None)
        gitignore_updates = update_gitignore()
        progress.update(task, description=f"✓ Added {gitignore_updates} .gitignore entries")
        
        # Check file permissions
        task = progress.add_task("Checking file permissions...", total=None)
        perm_fixes = check_file_permissions()
        progress.update(task, description=f"✓ Fixed {perm_fixes} file permissions")
        
        # Optimize repository
        task = progress.add_task("Optimizing git repository...", total=None)
        git_optimizations = optimize_repository()
        progress.update(task, description=f"✓ Completed {git_optimizations}/3 git optimizations")
        
        # Validate structure
        task = progress.add_task("Validating project structure...", total=None)
        missing_files, missing_dirs = validate_project_structure()
        if missing_files or missing_dirs:
            progress.update(task, description=f"⚠ Missing: {len(missing_files)} files, {len(missing_dirs)} dirs")
        else:
            progress.update(task, description="✓ Project structure is complete")
    
    # Summary
    console.print("\n[bold green]Maintenance Summary:[/bold green]")
    console.print(f"• Removed {cache_removed} cache files")
    console.print(f"• Removed {temp_removed} temporary files")
    console.print(f"• Updated .gitignore with {gitignore_updates} entries")
    console.print(f"• Fixed {perm_fixes} file permissions")
    console.print(f"• Completed {git_optimizations}/3 git optimizations")
    
    if missing_files:
        console.print(f"[yellow]• Missing files: {', '.join(missing_files)}[/yellow]")
    
    if missing_dirs:
        console.print(f"[yellow]• Missing directories: {', '.join(missing_dirs)}[/yellow]")
    
    # Recommendations
    console.print("\n[bold]Recommendations:[/bold]")
    console.print("• Run this maintenance script weekly")
    console.print("• Commit any .gitignore changes")
    console.print("• Address any missing files or directories")
    
    # Ask about committing changes
    if gitignore_updates > 0:
        if Confirm.ask("\nCommit .gitignore updates?"):
            success, stdout, stderr = run_command("git add .gitignore && git commit -m 'Update .gitignore with additional patterns'")
            if success:
                console.print("[green]✓ Committed .gitignore updates[/green]")
            else:
                console.print(f"[red]Failed to commit: {stderr}[/red]")

if __name__ == "__main__":
    main()
