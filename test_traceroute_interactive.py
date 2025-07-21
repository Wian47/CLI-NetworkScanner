#!/usr/bin/env python3
"""
Test script to debug traceroute interactive menu issues
"""

import sys
import time
from rich.console import Console
from modules.traceroute import Traceroute

def test_traceroute_interactive():
    """Test traceroute in a way similar to the interactive menu."""
    console = Console()
    
    # Test targets from the screenshot
    targets = ["127.0.0.1", "10.0.0.93"]
    
    for target in targets:
        console.print(f"\n[bold cyan]Testing traceroute to {target}[/bold cyan]")
        
        # Initialize traceroute (same as interactive menu)
        tr = Traceroute(console)
        
        # Add status message (same as interactive menu)
        with console.status("[bold green]Initializing traceroute...[/bold green]", spinner="dots"):
            time.sleep(0.5)  # Short pause for visual effect
        
        # Run traceroute with max_hops=30 (default from interactive menu)
        try:
            tr.trace(target, max_hops=30)
            console.print(f"[green]✓ Traceroute to {target} completed successfully[/green]")
        except Exception as e:
            console.print(f"[red]✗ Traceroute to {target} failed: {str(e)}[/red]")
        
        console.print("-" * 50)

if __name__ == "__main__":
    test_traceroute_interactive()
