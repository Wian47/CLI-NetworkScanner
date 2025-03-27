import subprocess
import re
import platform
import socket
import time
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

class Traceroute:
    """Traceroute module for NetworkScan Pro."""
    
    def __init__(self, console: Console):
        """Initialize traceroute with the console for output."""
        self.console = console
        
    def _parse_windows_tracert(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse the output of Windows tracert command.
        
        Args:
            output: Output string from tracert command
            
        Returns:
            List of dictionaries with hop information
        """
        hops = []
        
        # Split the output into lines
        lines = output.strip().split('\n')
        
        # Skip the first few lines (header)
        hop_lines = [line for line in lines if re.match(r'^\s*\d+', line)]
        
        for line in hop_lines:
            # Extract hop number
            hop_match = re.match(r'^\s*(\d+)', line)
            if not hop_match:
                continue
                
            hop_num = int(hop_match.group(1))
            
            # Extract RTTs
            rtts = re.findall(r'(\d+) ms', line)
            rtts = [int(rtt) for rtt in rtts]
            
            # Extract hostname/IP
            ip_match = re.search(r'\[([\d\.]+)\]', line)
            hostname_match = re.search(r'ms\s+([^\[]+)(?:\s+\[|$)', line)
            
            ip = ip_match.group(1) if ip_match else "*"
            hostname = hostname_match.group(1).strip() if hostname_match else "*"
            
            # Handle timeouts
            if "Request timed out" in line or "*" in line:
                ip = "*"
                hostname = "*"
                rtts = []
                
            hop = {
                "hop": hop_num,
                "ip": ip,
                "hostname": hostname,
                "rtts": rtts,
                "avg_rtt": sum(rtts) / len(rtts) if rtts else None,
                "asn": None,
                "isp": None
            }
            
            hops.append(hop)
            
        return hops
        
    def _parse_linux_traceroute(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse the output of Linux/Mac traceroute command.
        
        Args:
            output: Output string from traceroute command
            
        Returns:
            List of dictionaries with hop information
        """
        hops = []
        
        # Split the output into lines
        lines = output.strip().split('\n')
        
        # Skip the first line (header)
        hop_lines = lines[1:]
        
        for line in hop_lines:
            # Extract hop number
            hop_match = re.match(r'^\s*(\d+)', line)
            if not hop_match:
                continue
                
            hop_num = int(hop_match.group(1))
            
            # Extract hostname/IP
            name_ip_match = re.search(r'^\s*\d+\s+([^\s]+)\s+\(([\d\.]+)\)', line)
            
            if name_ip_match:
                hostname = name_ip_match.group(1)
                ip = name_ip_match.group(2)
            else:
                # Check for timeout
                if "*" in line:
                    hostname = "*"
                    ip = "*"
                else:
                    # Just IP, no hostname
                    ip_match = re.search(r'^\s*\d+\s+\(([\d\.]+)\)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        hostname = ip
                    else:
                        # Could not parse, skip this line
                        continue
                        
            # Extract RTTs
            rtts = re.findall(r'([\d\.]+) ms', line)
            rtts = [float(rtt) for rtt in rtts]
            
            hop = {
                "hop": hop_num,
                "ip": ip,
                "hostname": hostname,
                "rtts": rtts,
                "avg_rtt": sum(rtts) / len(rtts) if rtts else None,
                "asn": None,
                "isp": None
            }
            
            hops.append(hop)
            
        return hops
        
    def _get_asn_info(self, ip: str) -> Dict[str, Optional[str]]:
        """
        Try to get ASN information for an IP address.
        
        Args:
            ip: IP address
            
        Returns:
            Dictionary with ASN and ISP information
        """
        if ip == "*":
            return {"asn": None, "isp": None}
            
        # This is a simplified version. In a real implementation,
        # you would use a service like Team Cymru IP-to-ASN service, or
        # a local database like MaxMind GeoIP.
        # For simplicity, we'll just return placeholder values.
        
        return {
            "asn": "AS00000",
            "isp": "Unknown ISP"
        }
        
    def trace(self, target: str, max_hops: int = 30):
        """
        Perform a traceroute to a target.
        
        Args:
            target: Target IP address or hostname
            max_hops: Maximum number of hops
        """
        platform_name = platform.system()
        
        # Try to resolve the target to display IP
        try:
            ip = socket.gethostbyname(target)
            self.console.print(f"[bold]Tracing route to [yellow]{target} ({ip})[/yellow][/bold]")
        except socket.gaierror:
            self.console.print(f"[bold]Tracing route to [yellow]{target}[/yellow][/bold]")
            
        try:
            # Create progress spinner
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Tracing route to [yellow]{task.fields[target]}[/yellow]..."),
                console=self.console
            ) as progress:
                # Create task for progress tracking
                task_id = progress.add_task("Tracing...", target=target)
                
                if platform_name == "Windows":
                    # On Windows, use tracert
                    cmd = ["powershell", "-Command", f"tracert -d -h {max_hops} {target}"]
                    output = subprocess.check_output(cmd, text=True)
                    hops = self._parse_windows_tracert(output)
                else:
                    # On Linux/Mac, use traceroute
                    cmd = ["traceroute", "-n", "-m", str(max_hops), target]
                    output = subprocess.check_output(cmd, text=True)
                    hops = self._parse_linux_traceroute(output)
                
            # Try to get ASN information for each hop
            for hop in hops:
                if hop["ip"] != "*":
                    asn_info = self._get_asn_info(hop["ip"])
                    hop["asn"] = asn_info["asn"]
                    hop["isp"] = asn_info["isp"]
                    
            # Display results
            self._display_results(target, hops)
            
        except subprocess.CalledProcessError:
            self.console.print(f"[bold red]Error: Failed to perform traceroute to {target}[/bold red]")
        except Exception as e:
            self.console.print(f"[bold red]Error: {str(e)}[/bold red]")
            
    def _display_results(self, target: str, hops: List[Dict[str, Any]]):
        """
        Display traceroute results in a formatted table.
        
        Args:
            target: Target that was traced
            hops: List of dictionaries with hop information
        """
        # Create results table
        table = Table(title=f"Traceroute Results for {target}")
        table.add_column("Hop", style="cyan", justify="right")
        table.add_column("IP Address", style="yellow")
        table.add_column("Hostname", style="green")
        table.add_column("Avg RTT (ms)", style="magenta", justify="right")
        table.add_column("ASN", style="blue")
        table.add_column("ISP", style="white")
        
        for hop in hops:
            # Format values for display
            hop_num = str(hop["hop"])
            ip = hop["ip"]
            hostname = hop["hostname"]
            avg_rtt = f"{hop['avg_rtt']:.2f}" if hop["avg_rtt"] is not None else "*"
            asn = hop["asn"] or "*"
            isp = hop["isp"] or "*"
            
            # Use appropriate colors for timeouts
            if ip == "*":
                ip_display = f"[red]{ip}[/red]"
                hostname_display = f"[red]{hostname}[/red]"
                avg_rtt_display = f"[red]{avg_rtt}[/red]"
            else:
                ip_display = ip
                hostname_display = hostname
                avg_rtt_display = avg_rtt
                
            table.add_row(
                hop_num,
                ip_display,
                hostname_display,
                avg_rtt_display,
                asn,
                isp
            )
            
        self.console.print(table) 