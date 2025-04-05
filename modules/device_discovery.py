import socket
import subprocess
import threading
import ipaddress
import time
import sys
import re
import queue
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.text import Text
from rich import box

# Import database module
from database import ScanDatabase

class DeviceDiscovery:
    """Network device discovery module for NetworkScan Pro."""

    def __init__(self, console: Console = None):
        """Initialize the device discovery module."""
        self.console = console or Console()
        self.results = {}
        self.lock = threading.Lock()

        # Some common OUI prefixes for device identification
        self.oui_vendors = {
            "00:00:0C": "Cisco",
            "00:1A:11": "Google",
            "3C:22:FB": "Apple",
            "3C:5A:B4": "Google",
            "3C:D9:2B": "Hewlett Packard",
            "44:38:39": "Cumulus Networks",
            "48:DF:37": "Hewlett Packard Enterprise",
            "50:9A:4C": "Dell",
            "52:54:00": "QEMU/KVM",
            "54:52:00": "Proxmox/VirtualBox",
            "8C:85:90": "Apple",
            "B8:27:EB": "Raspberry Pi",
            "B8:CA:3A": "Dell",
            "C8:2A:14": "Apple",
            "E4:5F:01": "Raspberry Pi"
        }

    def _get_network_range(self, interface: str = None) -> str:
        """
        Get the network range for the specified or active interface.

        Args:
            interface: Network interface name (optional)

        Returns:
            CIDR network range (e.g., 192.168.1.0/24)
        """
        try:
            # For Windows
            if sys.platform == 'win32':
                # If interface not specified, get default gateway info
                if not interface:
                    output = subprocess.check_output("ipconfig", universal_newlines=True)
                    gateway_line = re.search(r"Default Gateway.*: ([0-9.]+)", output)
                    if gateway_line:
                        gateway = gateway_line.group(1)
                        # Extract the first three octets from the gateway
                        ip_prefix = ".".join(gateway.split(".")[:3])
                        return f"{ip_prefix}.0/24"

                # If we have a specific interface, get its IP/mask
                if interface:
                    output = subprocess.check_output(f"ipconfig", universal_newlines=True)
                    sections = output.split("\r\n\r\n")
                    for section in sections:
                        if interface.lower() in section.lower():
                            ip_match = re.search(r"IPv4 Address.*: ([0-9.]+)", section)
                            subnet_match = re.search(r"Subnet Mask.*: ([0-9.]+)", section)
                            if ip_match and subnet_match:
                                ip = ip_match.group(1)
                                mask = subnet_match.group(1)
                                network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                                return str(network)

            # For Linux/Mac
            else:
                # If interface not specified, find default interface
                if not interface:
                    # Get default gateway interface
                    if sys.platform == 'darwin':  # macOS
                        output = subprocess.check_output("route -n get default | grep interface",
                                                       shell=True, universal_newlines=True)
                        interface = output.split(":")[-1].strip()
                    else:  # Linux
                        output = subprocess.check_output("ip route | grep default",
                                                       shell=True, universal_newlines=True)
                        interface = output.split("dev")[1].split()[0].strip()

                # Get the IP and mask for the interface
                if sys.platform == 'darwin':  # macOS
                    output = subprocess.check_output(f"ifconfig {interface}",
                                                   shell=True, universal_newlines=True)
                    ip_match = re.search(r"inet ([0-9.]+) netmask 0x([0-9a-f]{8})", output)
                    if ip_match:
                        ip = ip_match.group(1)
                        hex_mask = ip_match.group(2)
                        # Convert hex mask to decimal
                        mask = ".".join(str(int(hex_mask[i:i+2], 16)) for i in range(0, 8, 2))
                        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                        return str(network)
                else:  # Linux
                    output = subprocess.check_output(f"ip addr show {interface}",
                                                   shell=True, universal_newlines=True)
                    ip_match = re.search(r"inet ([0-9.]+/[0-9]+)", output)
                    if ip_match:
                        return ip_match.group(1)

            # Fallback to common local network
            return "192.168.1.0/24"

        except Exception as e:
            self.console.print(f"[red]Error determining network range: {str(e)}[/red]")
            return "192.168.1.0/24"  # Fallback to common default

    def _get_network_interfaces(self) -> List[str]:
        """
        Get a list of available network interfaces.

        Returns:
            List of interface names
        """
        interfaces = []
        try:
            if sys.platform == 'win32':
                # Windows
                output = subprocess.check_output("ipconfig", universal_newlines=True)
                # Find adapter sections
                sections = output.split("\r\n\r\n")
                for section in sections:
                    if "adapter" in section.lower():
                        adapter_name = section.split(":")[0].strip()
                        if "adapter" in adapter_name.lower():
                            interfaces.append(adapter_name)

            elif sys.platform == 'darwin':
                # macOS
                output = subprocess.check_output("ifconfig", shell=True, universal_newlines=True)
                # Match interface names
                for line in output.split("\n"):
                    if ": flags=" in line:
                        interface = line.split(": flags=")[0].strip()
                        if not interface.startswith("lo"):  # Skip loopback
                            interfaces.append(interface)

            else:
                # Linux
                output = subprocess.check_output("ip link show", shell=True, universal_newlines=True)
                # Match interface names
                for line in output.split("\n"):
                    if ": " in line and "<" in line and ">" in line:
                        interface = line.split(": ")[1].split("@")[0].strip()
                        if not interface.startswith("lo"):  # Skip loopback
                            interfaces.append(interface)

        except Exception as e:
            self.console.print(f"[red]Error getting network interfaces: {str(e)}[/red]")

        return interfaces

    def _scan_worker(self, ip_queue: queue.Queue, progress: 'Progress', task_id: TaskID,
                    use_ping: bool = False, resolve_names: bool = True):
        """
        Worker function for threaded device scanning.

        Args:
            ip_queue: Queue of IP addresses to scan
            progress: Progress object for UI updates
            task_id: Task ID for progress tracking
            use_ping: Whether to use ping instead of ARP
            resolve_names: Whether to attempt hostname resolution
        """
        while not ip_queue.empty():
            try:
                ip = ip_queue.get(block=False)

                # Attempt to discover the device
                if use_ping:
                    is_up, mac, hostname = self._ping_device(ip, resolve_names)
                else:
                    is_up, mac, hostname = self._arp_device(ip, resolve_names)

                if is_up:
                    vendor = self._identify_device_vendor(mac)
                    with self.lock:
                        self.results[ip] = {
                            "ip": ip,
                            "mac": mac,
                            "hostname": hostname,
                            "vendor": vendor
                        }

                # Update progress
                progress.update(task_id, advance=1)

            except queue.Empty:
                break
            except Exception as e:
                self.console.print(f"[red]Error scanning {ip}: {str(e)}[/red]")
                progress.update(task_id, advance=1)
            finally:
                if not ip_queue.empty():
                    ip_queue.task_done()

    def _arp_device(self, ip: str, resolve_name: bool = True) -> tuple:
        """
        Check if a device is up using ARP.

        Args:
            ip: IP address to check
            resolve_name: Whether to attempt hostname resolution

        Returns:
            (is_up, mac_address, hostname)
        """
        try:
            # Try to import scapy for ARP scanning
            from scapy.all import ARP, Ether, srp, conf

            # Disable scapy output
            conf.verb = 0

            # Create ARP request packet
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast/arp_request

            # Send the packet and capture the response
            result = srp(packet, timeout=2, verbose=0)[0]

            if result:
                # Device responded
                mac = result[0][1].hwsrc
                hostname = ""

                # Try to get hostname
                if resolve_name:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = ""

                return True, mac, hostname

        except ImportError:
            # Scapy not available, use fallback ping method
            return self._ping_device(ip, resolve_name)

        except Exception as e:
            # Any other error, device might still be up but we can't confirm
            pass

        return False, "", ""

    def _ping_device(self, ip: str, resolve_name: bool = True) -> tuple:
        """
        Check if a device is up using ping.

        Args:
            ip: IP address to check
            resolve_name: Whether to attempt hostname resolution

        Returns:
            (is_up, mac_address, hostname)
        """
        is_up = False
        mac = ""
        hostname = ""

        try:
            # Construct ping command based on platform
            if sys.platform == "win32":
                ping_cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                ping_cmd = ["ping", "-c", "1", "-W", "1", ip]

            # Run the ping command
            subprocess.check_output(ping_cmd, stderr=subprocess.STDOUT)
            is_up = True

            # If the device is up, try to get its MAC address
            if is_up:
                if sys.platform == "win32":
                    # Use ARP table on Windows
                    arp_cmd = ["arp", "-a", ip]
                    output = subprocess.check_output(arp_cmd, universal_newlines=True)
                    mac_match = re.search(r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})", output)
                    if mac_match:
                        mac = mac_match.group(1)
                else:
                    # Use ARP table on Unix
                    arp_cmd = ["arp", "-n", ip]
                    output = subprocess.check_output(arp_cmd, universal_newlines=True)
                    mac_match = re.search(r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})", output)
                    if mac_match:
                        mac = mac_match.group(1)

            # Try to get hostname
            if resolve_name and is_up:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = ""

        except subprocess.CalledProcessError:
            # Ping failed, device is likely down
            pass
        except Exception as e:
            # Any other error
            pass

        return is_up, mac, hostname

    def _identify_device_vendor(self, mac: str) -> str:
        """
        Identify device vendor from MAC address.

        Args:
            mac: MAC address of the device

        Returns:
            Vendor name if found, or "Unknown"
        """
        if not mac:
            return "Unknown"

        # Normalize the MAC format to XX:XX:XX
        mac_prefix = mac.upper()
        if ":" in mac_prefix:
            mac_prefix = ":".join(mac_prefix.split(":")[:3])
        elif "-" in mac_prefix:
            mac_prefix = ":".join(mac_prefix.split("-")[:3])

        # Check our built-in database
        if mac_prefix in self.oui_vendors:
            return self.oui_vendors[mac_prefix]

        # Default vendor
        return "Unknown"

    def discover(self, network_range: str = None, interface: str = None,
                threads: int = 50, use_ping: bool = False, resolve_names: bool = True):
        """
        Discover devices on the network.

        Args:
            network_range: CIDR notation network range (e.g., 192.168.1.0/24)
            interface: Network interface to use
            threads: Number of threads to use
            use_ping: Whether to use ping instead of ARP
            resolve_names: Whether to attempt hostname resolution
        """
        self.results = {}

        # Get network range if not specified
        if not network_range:
            network_range = self._get_network_range(interface)

        # Parse the network range
        try:
            network = ipaddress.IPv4Network(network_range)

            self.console.print(f"\n[bold cyan]Starting device discovery on [yellow]{network}[/yellow]...[/bold cyan]")

            # Use ARP by default, but allow ping as fallback
            scan_method = "ARP scan"
            if use_ping:
                scan_method = "PING sweep"

            self.console.print(f"[cyan]Using [yellow]{scan_method}[/yellow] with [yellow]{threads}[/yellow] threads[/cyan]")
            self.console.print(f"[cyan]Hostname resolution is [yellow]{'enabled' if resolve_names else 'disabled'}[/yellow][/cyan]")

            # Queue of IPs to scan
            ip_queue = queue.Queue()
            for ip in network.hosts():
                ip_queue.put(str(ip))

            total_ips = ip_queue.qsize()

            # Create progress bar
            with Progress() as progress:
                task = progress.add_task(f"[cyan]Scanning network...", total=total_ips)

                # Create and start threads
                scan_threads = []
                for _ in range(min(threads, total_ips)):
                    thread = threading.Thread(
                        target=self._scan_worker,
                        args=(ip_queue, progress, task, use_ping, resolve_names)
                    )
                    thread.daemon = True
                    scan_threads.append(thread)
                    thread.start()

                # Wait for all threads to finish
                for thread in scan_threads:
                    thread.join()

            # Display the results
            self._display_results(network_range)

        except ValueError as e:
            self.console.print(f"[bold red]Error:[/bold red] Invalid network range {network_range}. Please use CIDR notation (e.g., 192.168.1.0/24)")

    def _display_results(self, network_range: str):
        """
        Display device discovery results in a table and save to database.

        Args:
            network_range: The network range that was scanned
        """
        device_count = len(self.results)

        if device_count == 0:
            self.console.print(f"\n[bold yellow]No devices found on {network_range}[/bold yellow]")
            return

        # Save results to database
        self._save_to_database(network_range)

        self.console.print(f"\n[bold green]Found [yellow]{device_count}[/yellow] devices on [yellow]{network_range}[/bold green]")

        # Create results table
        table = Table(
            title=f"Network Devices on {network_range}",
            box=box.ROUNDED,
            title_style="bold cyan",
            border_style="blue",
            header_style="bold cyan"
        )

        # Add columns
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="magenta")
        table.add_column("Hostname", style="green")
        table.add_column("Vendor/Device Type", style="yellow")

        # Sort devices by IP
        sorted_devices = sorted(self.results.values(),
                               key=lambda x: [int(octet) for octet in x["ip"].split(".")])

        # Add each device to the table
        for device in sorted_devices:
            hostname = device["hostname"] or "[dim]Unknown[/dim]"
            vendor = device["vendor"] or "[dim]Unknown[/dim]"

            table.add_row(
                device["ip"],
                device["mac"] or "[dim]N/A[/dim]",
                hostname,
                vendor
            )

        self.console.print(table)

        # Display summary info
        known_vendors = {}
        unknown_count = 0
        for device in self.results.values():
            if device["vendor"] and device["vendor"] != "Unknown":
                known_vendors[device["vendor"]] = known_vendors.get(device["vendor"], 0) + 1
            else:
                unknown_count += 1

        # Create vendor summary panel if we have known vendors
        if known_vendors:
            vendor_text = Text()
            for vendor, count in sorted(known_vendors.items(), key=lambda x: x[1], reverse=True):
                vendor_text.append(f"{vendor}: ", style="cyan")
                vendor_text.append(f"{count}\n", style="yellow")

            if unknown_count > 0:
                vendor_text.append(f"Unknown: ", style="dim cyan")
                vendor_text.append(f"{unknown_count}", style="dim yellow")

            vendor_panel = Panel(
                vendor_text,
                title="Device Types",
                border_style="blue",
                padding=(1, 2)
            )

            self.console.print(vendor_panel)

        # Inform user that results have been saved
        self.console.print("[green]✓ Scan results have been saved to the database.[/green]")
        self.console.print("[dim]You can view and compare scan history from the main menu.[/dim]")

    def _save_to_database(self, network_range: str):
        """
        Save device discovery results to the database.

        Args:
            network_range: The network range that was scanned
        """
        try:
            # Connect to the database
            db = ScanDatabase()

            # Create a new scan entry
            scan_metadata = {
                "network_range": network_range,
                "device_count": len(self.results),
                "scan_method": "ARP/Ping"
            }

            # Add the scan to the database
            scan_id = db.add_scan(
                scan_type="device_discovery",
                target=network_range,
                description=f"Device discovery on {network_range} ({len(self.results)} devices found)",
                metadata=scan_metadata
            )

            # Add all device results to the database
            for ip, device in self.results.items():
                db.add_device_discovery_result(
                    scan_id=scan_id,
                    ip_address=device["ip"],
                    mac_address=device["mac"] if device["mac"] else None,
                    hostname=device["hostname"] if device["hostname"] else None,
                    device_type=None,  # We don't have device type information yet
                    vendor=device["vendor"] if device["vendor"] != "Unknown" else None
                )

            # Close the database connection
            db.close()

        except Exception as e:
            self.console.print(f"[red]Error saving scan results to database: {str(e)}[/red]")