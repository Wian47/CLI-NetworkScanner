import subprocess
import socket
import platform
import re
import requests
import psutil
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

class NetworkInfo:
    """Network information module for NetworkScan Pro."""
    
    def __init__(self, console: Console):
        """Initialize network info with the console for output."""
        self.console = console
        
    def get_local_ip(self) -> Dict[str, Any]:
        """
        Get local IP configuration information.
        
        Returns:
            Dictionary with local IP information
        """
        # Get hostname
        hostname = socket.gethostname()
        
        # Get local IP by creating a socket connection
        local_ip = "127.0.0.1"  # Default fallback
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Doesn't need to be reachable
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            pass
            
        # Get all network interfaces
        interfaces = []
        
        try:
            # Get all available network interfaces using psutil
            network_interfaces = psutil.net_if_addrs()
            
            for interface_name, addr_list in network_interfaces.items():
                interface_info = {
                    "name": interface_name,
                    "ipv4": [],
                    "ipv6": [],
                    "mac": None
                }
                
                for addr in addr_list:
                    if addr.family == socket.AF_INET:  # IPv4
                        interface_info["ipv4"].append(addr.address)
                    elif addr.family == socket.AF_INET6:  # IPv6
                        interface_info["ipv6"].append(addr.address)
                    elif getattr(addr, 'family', None) == psutil.AF_LINK:  # MAC
                        interface_info["mac"] = addr.address
                        
                interfaces.append(interface_info)
                
        except Exception as e:
            self.console.print(f"[bold red]Error getting network interfaces: {str(e)}[/bold red]")
            
        return {
            "hostname": hostname,
            "local_ip": local_ip,
            "interfaces": interfaces
        }
        
    def get_public_ip(self) -> Dict[str, Any]:
        """
        Get public IP information.
        
        Returns:
            Dictionary with public IP information
        """
        result = {
            "public_ip": None,
            "country": None,
            "city": None,
            "isp": None
        }
        
        try:
            # Use ipify API to get public IP
            response = requests.get("https://api.ipify.org?format=json", timeout=5)
            if response.status_code == 200:
                result["public_ip"] = response.json().get("ip")
                
            # Try to get geolocation data (basic)
            # Note: In a real-world app, you would use a proper geolocation API
            # or local database. This is a simplified implementation.
            if result["public_ip"]:
                result["country"] = "Unknown"
                result["city"] = "Unknown"
                result["isp"] = "Unknown"
                
        except Exception as e:
            self.console.print(f"[bold yellow]Warning: Could not determine public IP: {str(e)}[/bold yellow]")
            
        return result
        
    def get_interface_stats(self) -> List[Dict[str, Any]]:
        """
        Get network interface statistics.
        
        Returns:
            List of dictionaries with interface statistics
        """
        try:
            # Get network interface statistics
            net_io = psutil.net_io_counters(pernic=True)
            
            stats = []
            for interface, io_stats in net_io.items():
                stats.append({
                    "interface": interface,
                    "bytes_sent": io_stats.bytes_sent,
                    "bytes_recv": io_stats.bytes_recv,
                    "packets_sent": io_stats.packets_sent,
                    "packets_recv": io_stats.packets_recv,
                    "errin": getattr(io_stats, "errin", 0),
                    "errout": getattr(io_stats, "errout", 0),
                    "dropin": getattr(io_stats, "dropin", 0),
                    "dropout": getattr(io_stats, "dropout", 0)
                })
                
            return stats
            
        except Exception as e:
            self.console.print(f"[bold red]Error getting interface statistics: {str(e)}[/bold red]")
            return []
            
    def show_local_ip(self):
        """Display local IP configuration information."""
        self.console.print("[bold]Retrieving local IP configuration...[/bold]")
        
        # Get local IP information - do this directly instead of in a live progress display
        ip_info = self.get_local_ip()
        
        # Now show a simple message that we're done
        self.console.print("[bold green]✓[/bold green] Network information retrieved successfully")
        
        # Display hostname and primary IP
        self.console.print(Panel(
            f"[bold cyan]Hostname:[/bold cyan] [yellow]{ip_info['hostname']}[/yellow]\n"
            f"[bold cyan]Primary IP:[/bold cyan] [yellow]{ip_info['local_ip']}[/yellow]",
            title="System Information",
            border_style="blue"
        ))
        
        # Display interfaces
        table = Table(title="Network Interfaces")
        table.add_column("Interface", style="cyan")
        table.add_column("IPv4 Addresses", style="yellow")
        table.add_column("IPv6 Addresses", style="green")
        table.add_column("MAC Address", style="magenta")
        
        for interface in ip_info["interfaces"]:
            name = interface["name"]
            ipv4 = ", ".join(interface["ipv4"]) if interface["ipv4"] else "None"
            ipv6 = ", ".join(interface["ipv6"]) if interface["ipv6"] else "None"
            mac = interface["mac"] or "None"
            
            table.add_row(name, ipv4, ipv6, mac)
            
        self.console.print(table)
            
    def show_public_ip(self):
        """Display public IP information."""
        self.console.print("[bold]Retrieving public IP information...[/bold]")
        
        # Get public IP information directly
        ip_info = self.get_public_ip()
        
        # Simple completion message
        self.console.print("[bold green]✓[/bold green] Public IP information retrieved")
        
        if ip_info["public_ip"]:
            # Display public IP information
            self.console.print(Panel(
                f"[bold cyan]Public IP:[/bold cyan] [yellow]{ip_info['public_ip']}[/yellow]\n"
                f"[bold cyan]Country:[/bold cyan] [yellow]{ip_info['country']}[/yellow]\n"
                f"[bold cyan]City:[/bold cyan] [yellow]{ip_info['city']}[/yellow]\n"
                f"[bold cyan]ISP:[/bold cyan] [yellow]{ip_info['isp']}[/yellow]",
                title="Public IP Information",
                border_style="green"
            ))
        else:
            self.console.print("[bold red]Could not determine public IP address.[/bold red]")
            
    def show_interface_stats(self):
        """Display network interface statistics."""
        self.console.print("[bold]Retrieving interface statistics...[/bold]")
        
        # Get interface statistics directly
        stats = self.get_interface_stats()
        
        # Simple completion message
        self.console.print("[bold green]✓[/bold green] Interface statistics retrieved")
        
        if stats:
            # Display interface statistics
            table = Table(title="Network Interface Statistics")
            table.add_column("Interface", style="cyan")
            table.add_column("Bytes Sent", style="green", justify="right")
            table.add_column("Bytes Received", style="yellow", justify="right")
            table.add_column("Packets Sent", style="green", justify="right")
            table.add_column("Packets Received", style="yellow", justify="right")
            table.add_column("Errors In", style="red", justify="right")
            table.add_column("Errors Out", style="red", justify="right")
            
            for interface in stats:
                name = interface["interface"]
                bytes_sent = self._format_bytes(interface["bytes_sent"])
                bytes_recv = self._format_bytes(interface["bytes_recv"])
                packets_sent = str(interface["packets_sent"])
                packets_recv = str(interface["packets_recv"])
                errin = str(interface["errin"])
                errout = str(interface["errout"])
                
                table.add_row(
                    name, bytes_sent, bytes_recv, packets_sent, packets_recv, errin, errout
                )
                
            self.console.print(table)
        else:
            self.console.print("[bold red]Could not retrieve interface statistics.[/bold red]")
            
    def _format_bytes(self, bytes: int) -> str:
        """
        Format bytes into a human-readable string.
        
        Args:
            bytes: Number of bytes
            
        Returns:
            Formatted string (e.g., "4.2 MB")
        """
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
            
        return f"{bytes:.2f} PB" 