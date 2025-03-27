import time
import psutil
import threading
from typing import Dict, List, Optional, Tuple, Union
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.progress import BarColumn, Progress
from rich.layout import Layout
from rich import box
from rich.text import Text
from collections import deque


class BandwidthMonitor:
    """Bandwidth monitoring module for NetworkScan Pro."""
    
    def __init__(self, console: Console = None):
        """Initialize the bandwidth monitor."""
        self.console = console or Console()
        self.stop_monitoring = False
        self.interval = 1.0  # Default update interval in seconds
        self.max_history = 60  # Store up to 60 data points (1 minute at 1s interval)
        self.history = {
            'time': deque(maxlen=self.max_history),
            'download': deque(maxlen=self.max_history),
            'upload': deque(maxlen=self.max_history)
        }
        self.total_received = 0
        self.total_sent = 0
        self.peak_download = 0
        self.peak_upload = 0
        self.start_time = 0
        self.max_graph_height = 20  # Characters for graph height
        
    def _get_network_stats(self, interface: Optional[str] = None) -> Tuple[Dict, Dict]:
        """
        Get current network statistics.
        
        Args:
            interface: Specific interface to monitor (None for all)
            
        Returns:
            Tuple of (current_stats, bytes_since_last)
        """
        # Get current network counters
        current_stats = psutil.net_io_counters(pernic=True) if interface else psutil.net_io_counters()
        
        # If we're tracking a specific interface
        if interface and interface in current_stats:
            current_stats = current_stats[interface]
            
        # If this is the first call, we don't have a previous value
        if not hasattr(self, 'last_stats'):
            self.last_stats = current_stats
            bytes_since_last = {'bytes_recv': 0, 'bytes_sent': 0}
        else:
            # Handle different return types from psutil depending on interface parameter
            if isinstance(current_stats, dict) and isinstance(self.last_stats, dict):
                # Calculate bytes transferred since last check
                bytes_since_last = {}
                for intf, stats in current_stats.items():
                    if intf in self.last_stats:
                        bytes_since_last[intf] = {
                            'bytes_recv': stats.bytes_recv - self.last_stats[intf].bytes_recv,
                            'bytes_sent': stats.bytes_sent - self.last_stats[intf].bytes_sent
                        }
                # Sum up all interfaces if not tracking a specific one
                total_recv = sum(stats['bytes_recv'] for stats in bytes_since_last.values())
                total_sent = sum(stats['bytes_sent'] for stats in bytes_since_last.values())
                bytes_since_last = {'bytes_recv': total_recv, 'bytes_sent': total_sent}
            else:
                # Direct psutil.net_io_counter object for single interface
                bytes_since_last = {
                    'bytes_recv': current_stats.bytes_recv - self.last_stats.bytes_recv,
                    'bytes_sent': current_stats.bytes_sent - self.last_stats.bytes_sent
                }
                
        # Store for next call
        self.last_stats = current_stats
        
        return current_stats, bytes_since_last
    
    def _format_bytes(self, bytes_val: float, include_bytes: bool = False) -> str:
        """
        Format bytes to human-readable string.
        
        Args:
            bytes_val: Value in bytes
            include_bytes: Whether to include the raw bytes in parentheses
            
        Returns:
            Formatted string
        """
        if bytes_val < 1024:
            formatted = f"{bytes_val:.2f} B/s"
        elif bytes_val < 1024 * 1024:
            formatted = f"{bytes_val / 1024:.2f} KB/s"
        elif bytes_val < 1024 * 1024 * 1024:
            formatted = f"{bytes_val / (1024 * 1024):.2f} MB/s"
        else:
            formatted = f"{bytes_val / (1024 * 1024 * 1024):.2f} GB/s"
            
        if include_bytes and bytes_val > 1024:
            formatted += f" ({bytes_val} B/s)"
            
        return formatted
    
    def _get_available_interfaces(self) -> Dict[str, Dict]:
        """
        Get all available network interfaces with stats.
        
        Returns:
            Dictionary of interfaces with their addresses
        """
        interfaces = {}
        addrs = psutil.net_if_addrs()
        stats = psutil.net_io_counters(pernic=True)
        
        for interface, addresses in addrs.items():
            # Skip any interfaces that don't have IPv4 addresses
            ip = None
            for addr in addresses:
                if addr.family == 2:  # AF_INET (IPv4)
                    ip = addr.address
                    break
                    
            # Skip interfaces without IPv4
            if not ip:
                continue
                
            # Skip interfaces that don't have stats
            if interface not in stats:
                continue
                
            interfaces[interface] = {
                'ip': ip,
                'stats': stats[interface]
            }
            
        return interfaces
    
    def _monitor_worker(self, interface: Optional[str] = None):
        """
        Worker function for monitoring bandwidth.
        
        Args:
            interface: Specific interface to monitor (None for all)
        """
        self.start_time = time.time()
        elapsed_time = 0
        
        # Get initial stats
        _, _ = self._get_network_stats(interface)
        
        while not self.stop_monitoring:
            # Get stats since last check
            current_stats, bytes_since_last = self._get_network_stats(interface)
            
            # Calculate bytes per second
            download_bps = bytes_since_last['bytes_recv'] / self.interval
            upload_bps = bytes_since_last['bytes_sent'] / self.interval
            
            # Update peak values
            self.peak_download = max(self.peak_download, download_bps)
            self.peak_upload = max(self.peak_upload, upload_bps)
            
            # Update totals
            self.total_received += bytes_since_last['bytes_recv']
            self.total_sent += bytes_since_last['bytes_sent']
            
            # Update history
            elapsed_time += self.interval
            self.history['time'].append(elapsed_time)
            self.history['download'].append(download_bps)
            self.history['upload'].append(upload_bps)
            
            # Sleep for the interval
            time.sleep(self.interval)
    
    def _get_monitoring_display(self, interface: Optional[str] = None) -> Layout:
        """
        Create a rich layout for displaying bandwidth monitoring.
        
        Args:
            interface: Specific interface being monitored (None for all)
            
        Returns:
            Rich Layout object
        """
        # Create the overall layout
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="stats"),
            Layout(name="graph", ratio=2)
        )
        
        # Create header panel
        interface_name = interface or "All Interfaces"
        elapsed = time.time() - self.start_time
        minutes, seconds = divmod(int(elapsed), 60)
        hours, minutes = divmod(minutes, 60)
        elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        
        header = Panel(
            f"[bold yellow]Monitoring network traffic on [green]{interface_name}[/green] - "
            f"Press Ctrl+C to stop - Elapsed: {elapsed_str}[/bold yellow]",
            border_style="yellow",
            padding=(1, 2)
        )
        
        # Create stats table
        stats_table = Table(
            title="Bandwidth Statistics",
            box=box.ROUNDED,
            border_style="blue",
            header_style="bold cyan",
            padding=(0, 1)
        )
        
        # Add columns for the stats table
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Current", style="green")
        stats_table.add_column("Peak", style="magenta")
        stats_table.add_column("Total", style="yellow")
        
        # Calculate current values
        if len(self.history['download']) > 0:
            current_download = self.history['download'][-1]
            current_upload = self.history['upload'][-1]
        else:
            current_download = 0
            current_upload = 0
            
        # Format values for display
        current_download_fmt = self._format_bytes(current_download)
        current_upload_fmt = self._format_bytes(current_upload)
        peak_download_fmt = self._format_bytes(self.peak_download)
        peak_upload_fmt = self._format_bytes(self.peak_upload)
        total_received_fmt = self._format_bytes(self.total_received).replace('/s', '')
        total_sent_fmt = self._format_bytes(self.total_sent).replace('/s', '')
        
        # Add rows to stats table
        stats_table.add_row("Download", current_download_fmt, peak_download_fmt, total_received_fmt)
        stats_table.add_row("Upload", current_upload_fmt, peak_upload_fmt, total_sent_fmt)
        
        # Create bandwidth graph
        if len(self.history['download']) > 1:
            # Get the data for the graph
            download_data = list(self.history['download'])
            upload_data = list(self.history['upload'])
            time_data = list(self.history['time'])
            
            # Find the maximum value for scaling
            max_value = max(max(download_data), max(upload_data)) if download_data else 1
            
            # Create a graph panel
            graph_title = "Bandwidth Usage Over Time (recent 60 seconds)"
            if interface:
                graph_title += f" - Interface: {interface}"
                
            # Generate the graph
            graph_lines = self._create_bandwidth_graph(
                download_data, upload_data, time_data, max_value
            )
            
            graph_panel = Panel(
                Text('\n'.join(graph_lines)),
                title=graph_title,
                border_style="blue",
                padding=(1, 2)
            )
        else:
            # Not enough data yet
            graph_panel = Panel(
                "[dim]Collecting data for graph visualization...[/dim]",
                title="Bandwidth Usage Over Time",
                border_style="blue",
                padding=(1, 2)
            )
            
        # Update the layout sections
        layout["header"].update(header)
        layout["stats"].update(stats_table)
        layout["graph"].update(graph_panel)
        
        return layout
    
    def _create_bandwidth_graph(self, 
                              download_data: List[float], 
                              upload_data: List[float],
                              time_data: List[float],
                              max_value: float) -> List[str]:
        """
        Create a text-based bandwidth graph.
        
        Args:
            download_data: List of download rates
            upload_data: List of upload rates
            time_data: List of time points
            max_value: Maximum value for scaling
            
        Returns:
            List of strings representing the graph
        """
        # Constants for graph display
        graph_width = min(len(download_data), self.max_history)
        graph_height = self.max_graph_height
        
        # Characters for the graph
        download_char = "▓"  # Download bars
        upload_char = "▒"    # Upload bars (lighter shade)
        axis_char = "│"      # Y-axis
        baseline_char = "─"  # X-axis
        
        # Create the graph with proper scaling
        graph_lines = []
        
        # Add a header with max speed
        max_speed_fmt = self._format_bytes(max_value)
        graph_lines.append(f"Max: {max_speed_fmt} {' ' * (graph_width - len(max_speed_fmt) - 5)}")
        
        # Generate each line of the graph from top to bottom
        for y in range(graph_height, 0, -1):
            line = [axis_char]
            threshold = (y / graph_height) * max_value
            
            for x in range(min(graph_width, len(download_data))):
                # Index from the end to show most recent data
                idx = len(download_data) - graph_width + x if len(download_data) > graph_width else x
                
                download_val = download_data[idx]
                upload_val = upload_data[idx]
                
                # Determine character at this position
                if download_val >= threshold:
                    line.append(f"[green]{download_char}[/green]")
                elif upload_val >= threshold:
                    line.append(f"[red]{upload_char}[/red]")
                else:
                    line.append(" ")
                    
            graph_lines.append("".join(line))
            
        # Add the x-axis baseline
        baseline = f"{axis_char}{baseline_char * graph_width}"
        graph_lines.append(baseline)
        
        # Add a time axis label (most recent time point)
        if time_data:
            seconds_label = f"Last {int(time_data[-1] - time_data[0])} seconds" if len(time_data) > 1 else "Starting..."
            time_axis = f"0{' ' * (graph_width - len(seconds_label) - 1)}{seconds_label}"
            graph_lines.append(time_axis)
            
        # Add a legend
        legend = f"[green]{download_char}[/green] Download  [red]{upload_char}[/red] Upload"
        graph_lines.append(legend)
        
        return graph_lines
    
    def monitor(self, interface: Optional[str] = None, duration: Optional[int] = None, 
                update_interval: float = 1.0):
        """
        Start monitoring bandwidth usage.
        
        Args:
            interface: Specific interface to monitor (None for all)
            duration: Duration to monitor in seconds (None for indefinite)
            update_interval: Update interval in seconds
        """
        self.interval = update_interval
        self.stop_monitoring = False
        
        # Reset statistics
        self.total_received = 0
        self.total_sent = 0
        self.peak_download = 0
        self.peak_upload = 0
        self.history = {
            'time': deque(maxlen=self.max_history),
            'download': deque(maxlen=self.max_history),
            'upload': deque(maxlen=self.max_history)
        }
        
        # Display available interfaces
        interfaces = self._get_available_interfaces()
        if not interfaces:
            self.console.print("[bold red]Error:[/bold red] No active network interfaces found.")
            return
            
        if interface:
            self.console.print(f"[bold cyan]Monitoring interface: [yellow]{interface}[/yellow][/bold cyan]")
            if interface not in interfaces:
                self.console.print(f"[bold red]Warning:[/bold red] Interface {interface} not found. Available interfaces:")
                for name, details in interfaces.items():
                    self.console.print(f"  [yellow]{name}[/yellow] ({details['ip']})")
                return
        else:
            self.console.print("[bold cyan]Monitoring all network interfaces:[/bold cyan]")
            for name, details in interfaces.items():
                self.console.print(f"  [yellow]{name}[/yellow] ({details['ip']})")
        
        # Create and start the monitoring thread
        monitor_thread = threading.Thread(
            target=self._monitor_worker,
            args=(interface,)
        )
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Display the results in real-time using Rich Live
        try:
            with Live(self._get_monitoring_display(interface), refresh_per_second=4) as live:
                # If duration is specified, run for that long
                if duration:
                    end_time = time.time() + duration
                    while time.time() < end_time and not self.stop_monitoring:
                        live.update(self._get_monitoring_display(interface))
                        time.sleep(0.25)  # Quick updates for responsive UI
                else:
                    # Run indefinitely until stopped
                    while not self.stop_monitoring:
                        live.update(self._get_monitoring_display(interface))
                        time.sleep(0.25)  # Quick updates for responsive UI
                        
        except KeyboardInterrupt:
            self.stop_monitoring = True
            
        # Show summary after monitoring stops
        self._show_summary(interface)
        
    def _show_summary(self, interface: Optional[str] = None):
        """
        Show a summary of bandwidth usage.
        
        Args:
            interface: Specific interface that was monitored (None for all)
        """
        # Calculate total duration
        duration = time.time() - self.start_time
        
        # Create a summary panel
        interface_name = interface or "All Interfaces"
        
        # Format duration
        minutes, seconds = divmod(int(duration), 60)
        hours, minutes = divmod(minutes, 60)
        duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        
        # Create summary table
        summary_table = Table(
            title=f"Bandwidth Monitoring Summary - {interface_name}",
            box=box.ROUNDED,
            border_style="blue",
            padding=(0, 1)
        )
        
        # Add columns
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        
        # Add rows
        summary_table.add_row("Monitoring Duration", duration_str)
        summary_table.add_row("Total Downloaded", self._format_bytes(self.total_received).replace('/s', ''))
        summary_table.add_row("Total Uploaded", self._format_bytes(self.total_sent).replace('/s', ''))
        summary_table.add_row("Peak Download Speed", self._format_bytes(self.peak_download))
        summary_table.add_row("Peak Upload Speed", self._format_bytes(self.peak_upload))
        
        # Calculate averages if we have data
        if len(self.history['download']) > 0:
            avg_download = sum(self.history['download']) / len(self.history['download'])
            avg_upload = sum(self.history['upload']) / len(self.history['upload'])
            
            summary_table.add_row("Average Download Speed", self._format_bytes(avg_download))
            summary_table.add_row("Average Upload Speed", self._format_bytes(avg_upload))
        
        self.console.print("\n[bold yellow]━━━ Bandwidth Monitoring Complete ━━━[/bold yellow]", justify="center")
        self.console.print(summary_table) 