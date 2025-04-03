import socket
import threading
import time
import sys
import platform
import subprocess
import os
import queue
from typing import List, Dict, Any, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn, TaskProgressColumn, TaskID
from rich.panel import Panel

# Import service identification module
from modules.service_identification import ServiceIdentifier

class PortScanner:
    """Port scanning module for NetworkScan Pro."""

    def __init__(self, console: Console = None):
        """Initialize the port scanner."""
        self.console = console or Console()
        self.results = {}
        self.lock = threading.Lock()
        self._use_advanced_scan = False

        # Initialize service identifier
        self.service_identifier = ServiceIdentifier(console)

        # Common port-service mappings for quick lookups
        self.port_services = {
            20: "FTP-data",
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            67: "DHCP-Server",
            68: "DHCP-Client",
            69: "TFTP",
            80: "HTTP",
            88: "Kerberos",
            110: "POP3",
            119: "NNTP",
            123: "NTP",
            137: "NetBIOS-NS",
            138: "NetBIOS-DGM",
            139: "NetBIOS-SSN",
            143: "IMAP",
            161: "SNMP",
            162: "SNMP-Trap",
            389: "LDAP",
            443: "HTTPS",
            445: "SMB",
            465: "SMTPS",
            587: "SMTP-Submission",
            636: "LDAPS",
            993: "IMAPS",
            995: "POP3S",
            1080: "SOCKS",
            1433: "MS-SQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            9000: "Jenkins"
        }

    def scan_port(self, ip: str, port: int) -> Dict[str, Any]:
        """
        Scan a single port on the target IP.

        Args:
            ip: Target IP address
            port: Port number to scan

        Returns:
            Dictionary with port status and information
        """
        # If we have advanced scanning available, use it
        if self._use_advanced_scan:
            try:
                return self._scan_port_syn(ip, port)
            except Exception as e:
                # Fall back to socket scanning if SYN scan fails
                self.console.print(f"[dim red]SYN scan failed, falling back to socket scan: {str(e)}[/dim red]")

        # Regular socket-based scanning (TCP connect)
        return self._scan_port_socket(ip, port)

    def _scan_port_socket(self, ip: str, port: int) -> Dict[str, Any]:
        """
        Scan a port using standard socket connection (TCP connect scan).

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

        # Determine timeout based on whether IP is local or public
        is_local_ip = ip.startswith(('10.', '172.16.', '192.168.', '127.'))
        # Use shorter timeout for local IPs, longer for external
        timeout = 0.5 if is_local_ip else 1.5

        # Create socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

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

                # For HTTP/HTTPS ports, try to get a response to confirm
                if port in [80, 443, 8080, 8443]:
                    self._check_http_response(ip, port, result)

            # If conn is not 0 but relatively quick, it's probably actively rejected
            elif response_time < timeout * 0.8:
                result["state"] = "closed"
            # If it's close to timeout value, it's probably filtered
            else:
                result["state"] = "filtered"

            s.close()
        except socket.timeout:
            result["state"] = "filtered"
            result["response_time"] = round(timeout * 1000, 2)
        except socket.error:
            # Connection error but fast response = closed
            response_time = time.time() - start_time
            result["response_time"] = round(response_time * 1000, 2)

            if response_time < timeout * 0.8:
                result["state"] = "closed"
            else:
                result["state"] = "filtered"
        except Exception as e:
            self.console.print(f"[red]Error scanning port {port}: {str(e)}[/red]")

        return result

    def _scan_port_syn(self, ip: str, port: int) -> Dict[str, Any]:
        """
        Scan a port using TCP SYN scan (half-open scan).
        Requires scapy and root/admin privileges.

        Args:
            ip: Target IP address
            port: Port number to scan

        Returns:
            Dictionary with port status and information
        """
        # Import scapy here to avoid dependency if not used
        try:
            from scapy.all import sr1, IP, TCP, ICMP
            from scapy.layers.inet import RandShort
        except ImportError:
            # Fall back to socket scan
            return self._scan_port_socket(ip, port)

        result = {
            "port": port,
            "state": "closed",
            "service": "unknown",
            "response_time": 0
        }

        # Determine timeout based on whether IP is local or public
        is_local_ip = ip.startswith(('10.', '172.16.', '192.168.', '127.'))
        timeout = 0.5 if is_local_ip else 2.0

        # Create SYN packet
        src_port = RandShort()
        syn_packet = IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S")

        # Record start time
        start_time = time.time()

        # Send packet and wait for response (with timeout)
        response = sr1(syn_packet, timeout=timeout, verbose=0)

        # Calculate response time
        response_time = time.time() - start_time
        result["response_time"] = round(response_time * 1000, 2)

        # Analyze response
        if response is None:
            result["state"] = "filtered"
        elif response.haslayer(TCP):
            # Check TCP flags
            tcp_flags = response.getlayer(TCP).flags
            if tcp_flags == 0x12:  # SYN-ACK
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

                # For HTTP/HTTPS ports, try to get a response to confirm
                if port in [80, 443, 8080, 8443]:
                    self._check_http_response(ip, port, result)
            elif tcp_flags == 0x14:  # RST-ACK
                result["state"] = "closed"
        elif response.haslayer(ICMP):
            icmp_type = response.getlayer(ICMP).type
            icmp_code = response.getlayer(ICMP).code
            if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                result["state"] = "filtered"

        return result

    def _check_http_response(self, ip: str, port: int, result: Dict[str, Any]):
        """
        Attempt to get an HTTP response from web ports to confirm they're really open.

        Args:
            ip: Target IP address
            port: Port number
            result: Result dictionary to update
        """
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{ip}:{port}"

        try:
            import urllib.request
            import urllib.error

            # Create a request with a short timeout
            req = urllib.request.Request(url)
            # Set User-Agent to avoid being blocked
            req.add_header('User-Agent', 'Mozilla/5.0 NetworkScanPro/1.0')

            # Try to get a response
            response = urllib.request.urlopen(req, timeout=2)

            # If we get here, the port is definitely open
            result["state"] = "open"

            # Try to identify the server
            server = response.getheader('Server')
            if server:
                result["service"] = f"{result['service']} ({server})"

        except (urllib.error.URLError, socket.timeout, ConnectionResetError):
            # If connection fails but original socket connected, port is still open
            # but might be running something other than HTTP
            pass
        except Exception as e:
            # Ignore other errors - we've already determined the port is open
            pass

    def _check_scan_capabilities(self) -> Tuple[bool, str]:
        """
        Check if advanced scanning capabilities are available.

        Returns:
            Tuple of (is_available, reason)
        """
        # First check if scapy is available
        try:
            import scapy.all
        except ImportError:
            return False, "Scapy library not available"

        # Check if we're running as root/admin
        if platform.system() == "Windows":
            # On Windows, check if running as admin
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if not is_admin:
                    return False, "Admin privileges required for SYN scanning"
            except:
                return False, "Unable to determine admin status"
        else:
            # On Unix-like systems, check if running as root
            if os.geteuid() != 0:
                return False, "Root privileges required for SYN scanning"

        return True, "Advanced scanning available"

    def scan(self, target: str, ports: List[int], threads: int = 100, advanced: bool = False):
        """
        Scan the given target for open ports.

        Args:
            target: The target IP address or hostname
            ports: List of ports to scan
            threads: Number of threads to use for scanning
            advanced: Whether to use advanced scanning techniques
        """
        self.results = {}
        self.console.print(f"\n[bold cyan]Starting scan of [yellow]{target}[/yellow]...[/bold cyan]")

        if advanced:
            self.console.print("[bold green]Using advanced TCP SYN scanning technique[/bold green]")
        else:
            self.console.print("[dim]Using standard TCP connect scanning[/dim]")

        # Try to resolve the hostname to IP address
        try:
            ip = socket.gethostbyname(target)
            if ip != target:
                self.console.print(f"[cyan]Resolved [yellow]{target}[/yellow] to [yellow]{ip}[/yellow][/cyan]")
            else:
                self.console.print(f"[cyan]Target IP: [yellow]{ip}[/yellow][/cyan]")
        except socket.gaierror:
            self.console.print(f"[bold red]Error:[/bold red] Could not resolve hostname {target}")
            return

        # Prepare to scan
        self.console.print(f"[cyan]Scanning [yellow]{len(ports)}[/yellow] ports with [yellow]{threads}[/yellow] threads[/cyan]")

        # Multi-threaded scanning
        port_queue = queue.Queue()
        for port in ports:
            port_queue.put(port)

        # Create a progress bar to track scanning
        from rich.progress import Progress

        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning ports...", total=len(ports))

            # Create and start threads
            scan_threads = []
            for _ in range(min(threads, len(ports))):
                thread = threading.Thread(
                    target=self._scan_worker,
                    args=(port_queue, target, ip, progress, task, advanced)
                )
                thread.daemon = True
                scan_threads.append(thread)
                thread.start()

            # Wait for all threads to finish
            for thread in scan_threads:
                thread.join()

            # Ensure the progress bar completes
            progress.update(task, completed=len(ports))

        # Display the results
        self._display_results(target, ip)

    def _scan_worker(self, port_queue: queue.Queue, target: str, ip: str,
                    progress: 'Progress', task_id: TaskID, advanced: bool):
        """Worker function for threaded port scanning."""
        while not port_queue.empty():
            try:
                port = port_queue.get(block=False)
                result = self._scan_port(target, ip, port, advanced)
                self.results[port] = result
                progress.update(task_id, advance=1)
            except queue.Empty:
                break
            except Exception as e:
                self.console.print(f"[bold red]Error scanning port:[/bold red] {str(e)}")
                progress.update(task_id, advance=1)
            finally:
                port_queue.task_done()

    def _scan_port(self, target: str, ip: str, port: int, advanced: bool) -> Dict[str, Any]:
        """
        Scan a specific port using either basic or advanced techniques.

        Args:
            target: Target hostname
            ip: Target IP
            port: Port to scan
            advanced: Whether to use advanced scanning techniques

        Returns:
            Dictionary with port scan results
        """
        start_time = time.time()
        result = {
            "port": port,
            "state": "closed",
            "service": self._get_service_name(port),
            "response_time": 0
        }

        if advanced:
            # Use SYN scan if available (requires root/administrator privileges)
            try:
                result = self._syn_scan(ip, port)
            except Exception as e:
                # Fall back to regular scan if SYN scan fails
                self.console.print(f"[yellow]SYN scan failed, falling back to connect scan: {str(e)}[/yellow]")
                result = self._connect_scan(ip, port)
        else:
            # Use regular connect() scan
            result = self._connect_scan(ip, port)

        # Calculate response time
        elapsed = (time.time() - start_time) * 1000  # Convert to milliseconds
        result["response_time"] = round(elapsed, 2)

        return result

    def _connect_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """
        Perform a TCP connect scan on a port.

        Args:
            ip: Target IP
            port: Port to scan

        Returns:
            Dictionary with scan results
        """
        result = {
            "port": port,
            "state": "closed",
            "service": self._get_service_name(port)
        }

        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)  # Shorter timeout for faster scanning

        try:
            # Try to connect to the port
            s.connect((ip, port))
            result["state"] = "open"

            # For some common ports, try to get banner
            # For some common ports, try to get banner and identify service
            try:
                s.settimeout(0.5)  # Short timeout for banner grabbing
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    # Basic banner info for display
                    result["service"] += f" ({banner.splitlines()[0]})"

                    # Detailed service identification
                    service_info = self.service_identifier.identify_service(ip, port, banner)
                    if service_info["service_name"] != "Unknown":
                        result["service_details"] = service_info
            except:
                pass

        except socket.timeout:
            # Connection timed out - probably filtered
            result["state"] = "filtered"
        except ConnectionRefusedError:
            # Connection refused - port is closed
            result["state"] = "closed"
        except OSError as e:
            # Handle other network errors
            if "unreachable" in str(e).lower():
                result["state"] = "filtered"
            else:
                result["state"] = "closed"
        except Exception as e:
            # Handle any other exceptions
            result["state"] = "filtered"
        finally:
            s.close()

        return result

    def _syn_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """
        Perform a SYN scan on a port (more stealthy).
        Requires root/administrator privileges.

        Args:
            ip: Target IP
            port: Port to scan

        Returns:
            Dictionary with scan results
        """
        try:
            from scapy.all import sr1, IP, TCP, conf

            # Suppress Scapy output
            conf.verb = 0

            result = {
                "port": port,
                "state": "filtered",  # Default state is filtered
                "service": self._get_service_name(port)
            }

            # Send SYN packet
            packet = IP(dst=ip)/TCP(dport=port, flags="S")
            response = sr1(packet, timeout=1.5)

            # Process the response
            if response is None:
                # No response - port is filtered
                result["state"] = "filtered"
            elif response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                # Check TCP flags
                if tcp_layer.flags == 0x12:  # SYN-ACK
                    # Port is open
                    result["state"] = "open"

                    # Send RST packet to close connection
                    rst_packet = IP(dst=ip)/TCP(dport=port, flags="R")
                    sr1(rst_packet, timeout=0.5, verbose=0)

                elif tcp_layer.flags == 0x14:  # RST-ACK
                    # Port is closed
                    result["state"] = "closed"
                else:
                    # Unknown response
                    result["state"] = "filtered"

            return result

        except ImportError:
            # Scapy not available
            raise Exception("Advanced scanning requires scapy module")
        except Exception as e:
            # Any other exception
            raise Exception(f"SYN scan error: {str(e)}")

    def _display_results(self, target: str, ip: str):
        """Display scan results in a formatted table."""
        open_ports = {port: info for port, info in self.results.items() if info["state"] == "open"}
        filtered_ports = {port: info for port, info in self.results.items() if info["state"] == "filtered"}
        closed_ports = {port: info for port, info in self.results.items() if info["state"] == "closed"}

        # Perform service identification for open ports that don't have it yet
        for port, info in open_ports.items():
            if "service_details" not in info:
                service_info = self.service_identifier.identify_service(ip, port)
                if service_info["service_name"] != "Unknown":
                    self.results[port]["service_details"] = service_info

        # Print summary
        self.console.print("\n[bold green]Scan Results:[/bold green]")
        self.console.print(f"[cyan]Target: [/cyan][yellow]{target} ({ip})[/yellow]")
        self.console.print(f"[cyan]Total ports scanned: [/cyan][yellow]{len(self.results)}[/yellow]")

        # Color the counts appropriately
        open_count = len(open_ports)
        open_color = "green" if open_count > 0 else "white"
        self.console.print(f"[cyan]Open ports: [/cyan][{open_color}]{open_count}[/{open_color}]")

        filtered_count = len(filtered_ports)
        filtered_color = "yellow" if filtered_count > 0 else "white"
        self.console.print(f"[cyan]Filtered ports: [/cyan][{filtered_color}]{filtered_count}[/{filtered_color}]")

        closed_count = len(closed_ports)
        self.console.print(f"[cyan]Closed ports: [/cyan][red]{closed_count}[/red]")

        # If we found filtered ports but no open ports, add an explanation
        if filtered_count > 0 and open_count == 0:
            self.console.print(Panel(
                "[yellow]⚠ Notice: [/yellow]Filtered ports were detected but no open ports were found.\n"
                "[dim]This could indicate:[/dim]\n"
                "• [yellow]Firewall is blocking the scan[/yellow]\n"
                "• [yellow]Target has no services running on scanned ports[/yellow]\n"
                "• [yellow]Network restrictions between you and the target[/yellow]",
                title="Scan Information",
                border_style="yellow"
            ))

        # Create results table
        from rich import box
        table = Table(
            title=f"Port Scan Results for {target}",
            box=box.ROUNDED,
            title_style="bold cyan",
            border_style="blue",
            header_style="bold cyan"
        )
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("State", style="green")
        table.add_column("Service", style="yellow")
        table.add_column("Version", style="yellow")
        table.add_column("Response Time (ms)", style="magenta", justify="right")
        table.add_column("Vulnerabilities", style="red")

        # Display HTTP accessibility results alongside port scanning results
        if 80 in self.results and self.results[80]["state"] != "open":
            http_result = self._check_http_directly(target, 80)
            if http_result["accessible"]:
                # Override port state if HTTP is actually accessible
                self.results[80]["state"] = "open"
                self.results[80]["service"] = f"HTTP ({http_result.get('server', 'unknown')})"
                open_ports[80] = self.results[80]

        if 443 in self.results and self.results[443]["state"] != "open":
            https_result = self._check_http_directly(target, 443)
            if https_result["accessible"]:
                # Override port state if HTTPS is actually accessible
                self.results[443]["state"] = "open"
                self.results[443]["service"] = f"HTTPS ({https_result.get('server', 'unknown')})"
                open_ports[443] = self.results[443]

        # Add open ports to table first (these are most important)
        open_port_count = 0
        for port, info in sorted(open_ports.items()):
            open_port_count += 1
            # Get version and vulnerability info if available
            version = "Unknown"
            vuln_count = 0

            if "service_details" in info:
                service_details = info["service_details"]
                if service_details["version"]:
                    version = service_details["version"]
                vuln_count = len(service_details["vulnerabilities"])

            # Add row with enhanced information
            table.add_row(
                str(info["port"]),
                f"[bold green]{info['state']}[/bold green]",
                info["service"],
                version,
                str(info["response_time"]),
                f"[bold red]{vuln_count}[/bold red]" if vuln_count > 0 else ""
            )

        # Add filtered ports with yellow highlighting - only show up to 5 filtered ports
        filtered_port_count = 0
        for port, info in sorted(filtered_ports.items())[:5]:
            filtered_port_count += 1
            table.add_row(
                str(info["port"]),
                f"[yellow]{info['state']}[/yellow]",
                info["service"],
                "",  # No version for filtered ports
                str(info["response_time"]),
                ""   # No vulnerabilities for filtered ports
            )

        # If too many filtered ports, just show summary
        if filtered_count > 5:
            table.add_row(
                "...",
                f"[yellow]...{filtered_count - 5} more filtered ports...[/yellow]",
                "",
                ""
            )

        # Only show a few closed ports as they're less interesting
        # Show at most 5 closed ports to save space
        closed_port_count = 0
        closed_sample = list(sorted(closed_ports.items()))[:5]
        for port, info in closed_sample:
            closed_port_count += 1
            table.add_row(
                str(info["port"]),
                f"[dim red]{info['state']}[/dim red]",
                info["service"],
                "",  # No version for closed ports
                str(info["response_time"]),
                ""   # No vulnerabilities for closed ports
            )

        if len(closed_ports) > 5:
            table.add_row(
                "...",
                f"[dim red]...{len(closed_ports) - 5} more closed ports...[/dim red]",
                "",
                ""
            )

        # Show nice message if no ports are shown at all
        if open_port_count + filtered_port_count + closed_port_count == 0:
            table.add_row("None", "[yellow]No ports scanned[/yellow]", "", "", "", "")

        self.console.print(table)

        # Display detailed service information for open ports with vulnerabilities
        vulnerable_ports = []
        for port, info in open_ports.items():
            if "service_details" in info and len(info["service_details"]["vulnerabilities"]) > 0:
                vulnerable_ports.append((port, info["service_details"]))

        if vulnerable_ports:
            self.console.print("\n[bold red]⚠ Potential Vulnerabilities Detected ⚠[/bold red]")

            for port, service_details in vulnerable_ports:
                self.console.print(f"\n[bold yellow]Port {port} - {service_details['service_name']} {service_details['version'] or ''}[/bold yellow]")
                self.service_identifier.display_service_info(service_details)

        # Add a footer with explanations of port states
        if open_count > 0 or filtered_count > 0:
            legend = "[bold green]open[/bold green]: Service is running and accepting connections\n"
            if filtered_count > 0:
                legend += "[yellow]filtered[/yellow]: Port is not responding (firewall/timeout)\n"
            if closed_count > 0:
                legend += "[dim red]closed[/dim red]: Port actively rejected the connection"

            self.console.print(Panel(
                legend,
                title="Port States Legend",
                border_style="blue"
            ))

    def _check_http_directly(self, target: str, port: int) -> Dict[str, Any]:
        """
        Check if HTTP/HTTPS is directly accessible.

        Args:
            target: Target hostname or IP
            port: Port number (80 or 443)

        Returns:
            Dictionary with accessibility info
        """
        result = {
            "accessible": False,
            "server": "unknown",
            "status": None
        }

        try:
            import urllib.request
            import urllib.error
            import ssl

            protocol = "https" if port == 443 else "http"

            # Create SSL context that ignores certificate errors
            context = ssl._create_unverified_context() if protocol == "https" else None

            # Try to connect
            request = urllib.request.Request(
                f"{protocol}://{target}",
                headers={'User-Agent': 'Mozilla/5.0 NetworkScanPro/1.0'}
            )

            # Set a short timeout
            if context:
                response = urllib.request.urlopen(request, timeout=3, context=context)
            else:
                response = urllib.request.urlopen(request, timeout=3)

            # If we get here, the port is accessible
            result["accessible"] = True
            result["status"] = response.status

            # Check for server header
            server = response.getheader('Server')
            if server:
                result["server"] = server

        except Exception as e:
            pass

        return result

    def _get_service_name(self, port: int) -> str:
        """
        Get the service name for a given port number.

        Args:
            port: Port number to lookup

        Returns:
            String with the service name
        """
        try:
            # Try to get from our predefined list first
            if port in self.port_services:
                return self.port_services[port]

            # Fall back to socket's getservbyport if available
            import socket
            return socket.getservbyport(port)
        except:
            return "Unknown"