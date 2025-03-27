import subprocess
import time
import re
import platform
import threading
from typing import List, Dict, Optional, Union
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.live import Live
from rich.align import Align

class PingUtility:
    """Ping utility module for NetworkScan Pro."""
    
    def __init__(self, console: Console):
        """Initialize ping utility with the console for output."""
        self.console = console
        self.stop_continuous = False
        
    def _parse_ping_output(self, output: str, platform_name: str) -> Dict[str, Union[str, float, int]]:
        """
        Parse the output of the ping command.
        
        Args:
            output: Output string from ping command
            platform_name: Platform name for OS-specific parsing
            
        Returns:
            Dictionary with parsed ping results
        """
        result = {
            "sent": 0,
            "received": 0,
            "loss": 100.0,
            "min_time": 0.0,
            "max_time": 0.0,
            "avg_time": 0.0,
            "times": [],
            "status": "failed"
        }
        
        # Find number of packets sent/received
        if platform_name == "Windows":
            # Find sent packets
            sent_match = re.search(r"Sent = (\d+)", output, re.IGNORECASE)
            if sent_match:
                result["sent"] = int(sent_match.group(1))
            else:
                # If we can't find the summary, but there's a ping, assume 1 sent
                if "Reply from" in output:
                    result["sent"] = 1
                
            # Find received packets
            received_match = re.search(r"Received = (\d+)", output, re.IGNORECASE)
            if received_match:
                result["received"] = int(received_match.group(1))
            else:
                # If we can't find the summary, but there's a reply, assume 1 received
                if "Reply from" in output:
                    result["received"] = 1
                
            # Calculate packet loss
            if result["sent"] > 0:
                result["loss"] = 100.0 - (result["received"] / result["sent"] * 100.0)
                
            # Find min/max/avg times
            times_match = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", output)
            if times_match:
                result["min_time"] = float(times_match.group(1))
                result["max_time"] = float(times_match.group(2))
                result["avg_time"] = float(times_match.group(3))
                
            # Extract individual time from Windows format
            time_matches = re.finditer(r"time[=<](\d+\.?\d*) ?ms", output, re.IGNORECASE)
            result["times"] = [float(match.group(1)) for match in time_matches]
                
        else:  # Linux/Mac
            # Find sent/received/loss
            stats_match = re.search(r"(\d+) packets transmitted, (\d+) received, (\d+\.?\d*)% packet loss", output)
            if stats_match:
                result["sent"] = int(stats_match.group(1))
                result["received"] = int(stats_match.group(2))
                result["loss"] = float(stats_match.group(3))
                
            # Find min/avg/max times
            times_match = re.search(r"min/avg/max(?:/mdev)? = (\d+\.?\d*)/(\d+\.?\d*)/(\d+\.?\d*)", output)
            if times_match:
                result["min_time"] = float(times_match.group(1))
                result["avg_time"] = float(times_match.group(2))
                result["max_time"] = float(times_match.group(3))
                
            # Extract individual times
            time_matches = re.finditer(r"time=(\d+\.?\d*) ?ms", output)
            result["times"] = [float(match.group(1)) for match in time_matches]
        
        # Set status
        if result["received"] > 0:
            result["status"] = "success"
            
        # Update min/max/avg if we have times but they weren't explicitly in the output
        if result["times"] and result["min_time"] == 0.0:
            result["min_time"] = min(result["times"])
            result["max_time"] = max(result["times"])
            result["avg_time"] = sum(result["times"]) / len(result["times"])
        
        return result

    def ping_once(self, target: str) -> Dict[str, Union[str, float, int]]:
        """
        Ping a target once.
        
        Args:
            target: Target IP address or hostname
            
        Returns:
            Dictionary with ping results
        """
        platform_name = platform.system()
        
        try:
            if platform_name == "Windows":
                # On Windows, use ping with PowerShell to ensure we get the output in a consistent format
                cmd = ["powershell", "-Command", f"ping -n 1 {target}"]
                
                # Use enhanced pattern to capture time in Windows output
                time_pattern = r"time[=<](\d+\.?\d*) ?ms"
            else:
                # On Linux/Mac, use -c 1 for one ping
                cmd = ["ping", "-c", "1", target]
                time_pattern = r"time=(\d+\.?\d*) ?ms"
                
            output = subprocess.check_output(cmd, text=True)
            
            # Directly extract time from output for more reliability
            time_match = re.search(time_pattern, output, re.IGNORECASE)
            response_time = float(time_match.group(1)) if time_match else None
            
            # Parse the rest of the output
            result = self._parse_ping_output(output, platform_name)
            
            # If we extracted a time directly but it's not in the parsed results, add it
            if response_time is not None and not result["times"]:
                result["times"] = [response_time]
                if result["received"] == 0:
                    result["received"] = 1
                    result["status"] = "success"
                    
            return result
            
        except subprocess.CalledProcessError:
            return {
                "sent": 1,
                "received": 0,
                "loss": 100.0,
                "min_time": 0.0,
                "max_time": 0.0,
                "avg_time": 0.0,
                "times": [],
                "status": "failed"
            }
        except Exception as e:
            self.console.print(f"[bold red]Error pinging {target}: {str(e)}[/bold red]")
            return {
                "sent": 0,
                "received": 0,
                "loss": 100.0,
                "min_time": 0.0,
                "max_time": 0.0,
                "avg_time": 0.0,
                "times": [],
                "status": "error",
                "error": str(e)
            }
    
    def ping(self, target: str, count: int = 4, continuous: bool = False):
        """
        Ping a target multiple times.
        
        Args:
            target: Target IP address or hostname
            count: Number of pings to send (ignored if continuous is True)
            continuous: Whether to ping continuously until stopped
        """
        platform_name = platform.system()
        self.stop_continuous = False
        
        # First, check if the target is reachable with a single ping
        self.console.print(f"[bold]Checking if [yellow]{target}[/yellow] is reachable...[/bold]")
        initial_result = self.ping_once(target)
        
        if initial_result["status"] == "failed":
            self.console.print(f"[bold red]Target {target} is not reachable.[/bold red]")
            return
            
        self.console.print(f"[bold green]Target [yellow]{target}[/yellow] is reachable![/bold green]")
        
        if continuous:
            # For continuous ping, we'll use our own implementation
            self.console.print(f"\n[bold cyan]Starting continuous ping to [yellow]{target}[/yellow][/bold cyan]")
            try:
                self._continuous_ping(target)
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Continuous ping stopped by user.[/yellow]")
        else:
            try:
                # For standard ping, use the system ping command
                # Prepare ping command based on platform
                if platform_name == "Windows":
                    cmd = ["powershell", "-Command", f"ping -n {count} {target}"]
                else:
                    cmd = ["ping", "-c", str(count), target]
                
                # Create progress spinner
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]Pinging [yellow]{task.fields[target]}[/yellow]..."),
                    console=self.console
                ) as progress:
                    # Create task for progress tracking
                    task_id = progress.add_task("Pinging...", target=target)
                    
                    # Run ping command
                    output = subprocess.check_output(cmd, text=True)
                    
                # Parse and display results
                result = self._parse_ping_output(output, platform_name)
                self._display_results(target, result)
                
            except subprocess.CalledProcessError:
                self.console.print(f"[bold red]Error: Failed to ping {target}[/bold red]")
            except Exception as e:
                self.console.print(f"[bold red]Error: {str(e)}[/bold red]")
                
    def _continuous_ping(self, target: str):
        """
        Ping a target continuously until stopped.
        
        Args:
            target: Target IP address or hostname
        """
        platform_name = platform.system()
        total_sent = 0
        total_received = 0
        times = []
        
        # Show title and instructions
        self.console.print(f"\n[bold cyan]Continuous Ping to {target}[/bold cyan]")
        self.console.print("[yellow]Press Ctrl+C to stop the continuous ping[/yellow]\n")
        
        try:
            while not self.stop_continuous:
                # Perform a single ping
                start_time = time.time()
                result = self.ping_once(target)
                ping_time = time.time() - start_time
                
                # Update totals
                total_sent += 1
                if result["status"] == "success":
                    total_received += 1
                    
                    # Update times list
                    if result["times"]:
                        times.append(result["times"][0])
                
                # Calculate statistics
                loss_percent = 0.0 if total_sent == 0 else 100.0 - (total_received / total_sent * 100.0)
                min_time = min(times) if times else 0.0
                avg_time = sum(times) / len(times) if times else 0.0
                max_time = max(times) if times else 0.0
                
                # Get the RTT for this ping
                if result["times"]:
                    last_rtt = f"{result['times'][0]:.2f} ms"
                else:
                    last_rtt = "Timeout"
                
                # Build a table to display the current results
                table = Table(show_header=True, title=f"Ping statistics after {total_sent} pings")
                table.add_column("Packets Sent", style="cyan", justify="right")
                table.add_column("Packets Received", style="green", justify="right")
                table.add_column("Packet Loss", style="yellow", justify="right")
                table.add_column("Last RTT", style="magenta", justify="right")
                table.add_column("Min RTT", style="blue", justify="right")
                table.add_column("Avg RTT", style="blue", justify="right")
                table.add_column("Max RTT", style="blue", justify="right")
                
                min_str = f"{min_time:.2f} ms" if times else "N/A"
                avg_str = f"{avg_time:.2f} ms" if times else "N/A"
                max_str = f"{max_time:.2f} ms" if times else "N/A"
                
                table.add_row(
                    str(total_sent),
                    str(total_received),
                    f"{loss_percent:.1f}%",
                    last_rtt,
                    min_str,
                    avg_str,
                    max_str
                )
                
                # Clear the console and print the new table
                self.console.clear()
                self.console.print(f"[bold cyan]Continuous Ping to {target}[/bold cyan]")
                self.console.print("[yellow]Press Ctrl+C to stop the continuous ping[/yellow]\n")
                self.console.print(table)
                
                # Wait before next ping
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.stop_continuous = True
            self.console.print("\n[yellow]Continuous ping stopped by user.[/yellow]")
                
    def _display_results(self, target: str, result: Dict[str, Union[str, float, int]]):
        """
        Display ping results in a formatted table.
        
        Args:
            target: Target that was pinged
            result: Dictionary with ping results
        """
        # Create summary table
        table = Table(title=f"Ping Results for {target}")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Packets Sent", str(result["sent"]))
        table.add_row("Packets Received", str(result["received"]))
        table.add_row("Packet Loss", f"{result['loss']:.1f}%")
        
        if result["received"] > 0:
            table.add_row("Minimum RTT", f"{result['min_time']:.2f} ms")
            table.add_row("Average RTT", f"{result['avg_time']:.2f} ms")
            table.add_row("Maximum RTT", f"{result['max_time']:.2f} ms")
            
        self.console.print(table)
        
        # Create status message
        if result["status"] == "success":
            status_color = "green"
            status_message = "Target is reachable"
        else:
            status_color = "red"
            status_message = "Target is not reachable"
            
        self.console.print(f"[bold {status_color}]{status_message}[/bold {status_color}]") 