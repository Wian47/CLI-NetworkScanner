import socket
import threading
import time
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn, TaskProgressColumn

class PortScanner:
    """Port scanning module for NetworkScan Pro."""
    
    def __init__(self, console: Console):
        """Initialize the scanner with the console for output."""
        self.console = console
        self.results = {}
        self.lock = threading.Lock()
        
    def scan_port(self, ip: str, port: int) -> Dict[str, Any]:
        """
        Scan a single port on the target IP.
        
        Args:
            ip: Target IP address
            port: Port number to scan
            
        Returns:
            Dictionary with port status and information
        """
        result = {
            "port": port,
            "state": "closed",
            "service": "unknown",
            "response_time": 0
        }
        
        # Create socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        
        # Record start time
        start_time = time.time()
        
        try:
            # Attempt to connect to the port
            conn = s.connect_ex((ip, port))
            
            # Calculate response time
            response_time = time.time() - start_time
            result["response_time"] = round(response_time * 1000, 2)  # Convert to ms
            
            if conn == 0:
                result["state"] = "open"
                
                # Try to determine service
                try:
                    service = socket.getservbyport(port)
                    result["service"] = service
                except:
                    # If the service lookup fails, use known common services
                    common_services = {
                        20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
                        25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS",
                        3306: "MySQL", 3389: "RDP", 8080: "HTTP-ALT"
                    }
                    result["service"] = common_services.get(port, "unknown")
                
            s.close()
        except socket.error:
            result["state"] = "filtered"
        except Exception as e:
            self.console.print(f"[red]Error scanning port {port}: {str(e)}[/red]")
            
        return result
    
    def worker(self, ip: str, ports: List[int], progress, task_id):
        """Worker thread to scan ports."""
        total_ports = len(ports)
        for i, port in enumerate(ports):
            result = self.scan_port(ip, port)
            
            with self.lock:
                self.results[port] = result
                
            # Update progress
            progress.update(task_id, advance=1)
            
    def scan(self, target: str, ports: List[int], num_threads: int = 20):
        """
        Scan a list of ports on the target.
        
        Args:
            target: Target IP address or hostname
            ports: List of ports to scan
            num_threads: Number of threads to use
        """
        self.results = {}
        
        try:
            # Resolve hostname to IP
            ip = socket.gethostbyname(target)
            self.console.print(f"[bold green]Starting scan on [/bold green][bold yellow]{target} ({ip})[/bold yellow]")
            self.console.print(f"[bold green]Scanning [/bold green][bold yellow]{len(ports)} ports[/bold yellow]")
        except socket.gaierror:
            self.console.print(f"[bold red]Could not resolve hostname: {target}[/bold red]")
            return
            
        # Set up progress bar
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            # Create task for progress tracking
            task_id = progress.add_task(f"[cyan]Scanning ports...", total=len(ports))
            
            # Split ports among threads
            thread_list = []
            chunk_size = max(1, len(ports) // num_threads)
            
            for i in range(0, len(ports), chunk_size):
                port_chunk = ports[i:i + chunk_size]
                t = threading.Thread(target=self.worker, args=(ip, port_chunk, progress, task_id))
                thread_list.append(t)
                t.start()
                
            # Wait for all threads to complete
            for t in thread_list:
                t.join()
                
        # Display results
        self._display_results(target, ip)
        
    def _display_results(self, target: str, ip: str):
        """Display scan results in a formatted table."""
        open_ports = {port: info for port, info in self.results.items() if info["state"] == "open"}
        filtered_ports = {port: info for port, info in self.results.items() if info["state"] == "filtered"}
        
        # Print summary
        self.console.print("\n[bold green]Scan Results:[/bold green]")
        self.console.print(f"[cyan]Target: [/cyan][yellow]{target} ({ip})[/yellow]")
        self.console.print(f"[cyan]Total ports scanned: [/cyan][yellow]{len(self.results)}[/yellow]")
        self.console.print(f"[cyan]Open ports: [/cyan][green]{len(open_ports)}[/green]")
        self.console.print(f"[cyan]Filtered ports: [/cyan][yellow]{len(filtered_ports)}[/yellow]")
        self.console.print(f"[cyan]Closed ports: [/cyan][red]{len(self.results) - len(open_ports) - len(filtered_ports)}[/red]")
        
        # Create results table
        table = Table(title=f"Port Scan Results for {target}")
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("State", style="green")
        table.add_column("Service", style="yellow")
        table.add_column("Response Time (ms)", style="magenta", justify="right")
        
        # Add open ports to table first
        for port, info in sorted(open_ports.items()):
            table.add_row(
                str(info["port"]),
                f"[green]{info['state']}[/green]",
                info["service"],
                str(info["response_time"])
            )
            
        # Add filtered ports
        for port, info in sorted(filtered_ports.items()):
            table.add_row(
                str(info["port"]),
                f"[yellow]{info['state']}[/yellow]",
                info["service"],
                str(info["response_time"])
            )
            
        # Only show a few closed ports as they're less interesting
        closed_ports = {port: info for port, info in self.results.items() 
                       if info["state"] == "closed"}
        
        # Show at most 5 closed ports to save space
        closed_sample = list(closed_ports.items())[:5]
        for port, info in sorted(closed_sample):
            table.add_row(
                str(info["port"]),
                f"[red]{info['state']}[/red]",
                info["service"],
                str(info["response_time"])
            )
            
        if len(closed_ports) > 5:
            table.add_row(
                "...",
                f"[red]...{len(closed_ports) - 5} more closed ports...[/red]",
                "",
                ""
            )
        
        self.console.print(table) 