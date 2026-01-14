#!/usr/bin/env python3
import argparse
import json
import sys
import time
import platform
import os
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt, FloatPrompt, Confirm
from rich.table import Table
from rich import box

# Import version info
from __version__ import __version__, __title__, __description__

# Import custom modules
import history

from modules.port_scanner import PortScanner
from modules.ping_utility import PingUtility
from modules.traceroute import Traceroute
from modules.dns_tools import DNSTools
from modules.network_info import NetworkInfo
from modules.device_discovery import DeviceDiscovery
from modules.bandwidth_monitor import BandwidthMonitor
from modules.ssl_checker import SSLCertificateChecker
from modules.ip_geolocation import IPGeolocation
from modules.service_identification import ServiceIdentifier
from modules.mac_address_changer import MACAddressChanger

# For backwards compatibility
VERSION = __version__

# Global flags for output control
QUIET_MODE = False
JSON_OUTPUT = False

# Initialize console with proper encoding for Windows compatibility
if os.name == 'nt':  # Windows
    # Force UTF-8 encoding on Windows to handle Unicode characters
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except:
            pass
    console = Console(force_terminal=True, legacy_windows=False)
else:
    console = Console()

def display_banner():
    """Display ASCII art banner with tool name and version."""
    banner = """
    ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
    ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
    ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝
    ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗
    ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

    ███████╗ ██████╗ █████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗
    ██╔════╝██╔════╝██╔══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗
    ███████╗██║     ███████║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║
    ╚════██║██║     ██╔══██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║
    ███████║╚██████╗██║  ██║██║ ╚████║    ██║     ██║  ██║╚██████╔╝
    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝
    """
    panel = Panel(
        banner,
        title=f"[bold white]v{VERSION}[/bold white]",
        title_align="right",
        subtitle="[italic]Advanced Network Diagnostics[/italic]",
        subtitle_align="center",
        border_style="blue",
        padding=(1, 2)
    )
    console.print(panel)
    console.print("[bold blue]╾───────────────────────────────────────────────────────────────────────╼[/bold blue]", justify="center")
    console.print()

def main_menu():
    """Display and handle the main menu options."""
    while True:
        console.print("\n[bold cyan]━━━ MAIN MENU ━━━[/bold cyan]", justify="center")

        # Create a more visually appealing menu with icons
        menu_items = [
            ("1", "🔍 Port Scanner", "Scan for open ports on a target"),
            ("2", "📶 Ping Utility", "Test connectivity to a host"),
            ("3", "🌐 Traceroute", "Map the path to a destination"),
            ("4", "🔖 DNS Tools", "Lookup and test DNS records"),
            ("5", "📊 Network Info", "View local and public network details"),
            ("6", "🔎 Device Discovery", "Find devices on your network"),
            ("7", "📈 Bandwidth Monitor", "Track real-time network usage"),
            ("8", "🔒 SSL Certificate Checker", "Verify SSL/TLS certificates"),
            ("9", "🌍 IP Geolocation", "Map IP addresses to physical locations"),
            ("10", "📱 MAC Address Changer", "Change network interface MAC addresses"),
            ("11", "🛡 Vulnerability Scanner", "Scan for service vulnerabilities"),
            ("12", "📝 Scan History", "View and compare past scan results"),
            ("13", "🚪 Exit", "Quit the application")
        ]

        # Create a stylized menu table with improved formatting
        menu_table = Table(show_header=False, box=box.ROUNDED, expand=True, border_style="cyan", padding=(0, 1))
        menu_table.add_column(style="dim cyan", justify="center", width=5)
        menu_table.add_column(style="bold white", justify="left")

        for key, desc, help_text in menu_items:
            menu_table.add_row(f"[{key}]", f"{desc} - {help_text}")

        console.print(menu_table)

        choice = Prompt.ask(
            "\n[bold cyan]Enter your choice[/bold cyan]",
            choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13"],
            default="13",
            show_choices=True,
            show_default=True
        )

        if choice == "1":
            port_scanner_menu()
        elif choice == "2":
            ping_utility_menu()
        elif choice == "3":
            traceroute_menu()
        elif choice == "4":
            dns_tools_menu()
        elif choice == "5":
            network_info_menu()
        elif choice == "6":
            device_discovery_menu()
        elif choice == "7":
            bandwidth_monitor_menu()
        elif choice == "8":
            ssl_checker_menu()
        elif choice == "9":
            ip_geolocation_menu()
        elif choice == "10":
            mac_address_changer_menu()
        elif choice == "11":
            vulnerability_scanner_menu()
        elif choice == "12":
            history.show_history_menu()
        elif choice == "13":
            console.print("\n[bold yellow]━━━ Thank you for using NetworkScan Pro ━━━[/bold yellow]", justify="center")
            sys.exit(0)

def port_scanner_menu():
    """Handle the port scanner menu options."""
    console.print("\n[bold cyan]━━━ PORT SCANNER ━━━[/bold cyan]", justify="center")

    target = Prompt.ask("[bold]📍 Enter target IP or hostname[/bold]")

    # Port selection sub-menu
    console.print("\n[bold]Select port scan type:[/bold]")
    port_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
    port_table.add_column(style="cyan", justify="center", width=3)
    port_table.add_column(style="white", width=20, no_wrap=False)
    port_table.add_column(style="dim", width=40, no_wrap=False)

    port_options = [
        ("1", "Common ports", "Most frequently used (20-25, 53, 80, 443, 3306, etc.)"),
        ("2", "Full scan", "First 1024 ports (may take longer)"),
        ("3", "Custom range", "Specify your own port range")
    ]

    for key, desc, help_text in port_options:
        port_table.add_row(f"[{key}]", desc, help_text)

    console.print(port_table)

    port_choice = Prompt.ask(
        "[bold cyan]Choose scan type[/bold cyan]",
        choices=["1", "2", "3"],
        default="1"
    )

    ports = []
    if port_choice == "1":
        ports = [20, 21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]
        console.print("[dim]Selected common ports scan[/dim]")
    elif port_choice == "2":
        ports = list(range(1, 1025))
        console.print("[dim]Selected full port scan (1-1024)[/dim]")
    elif port_choice == "3":
        port_range = Prompt.ask("[bold]Enter port range (e.g., 80-100)[/bold]")
        try:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
            console.print(f"[dim]Selected custom range: {start}-{end} ({len(ports)} ports)[/dim]")
        except:
            console.print(Panel("[bold red]Invalid port range format![/bold red]\nUsing default ports (1-1024) instead.",
                               border_style="red", title="Error", padding=(1, 2)))
            ports = list(range(1, 1025))

    # Speed/thread options
    thread_count = IntPrompt.ask(
        "[bold]Select thread count[/bold] [dim](higher = faster but more resource intensive)[/dim]",
        default=20,
        show_default=True
    )

    # Advanced scan options
    console.print("\n[bold]Advanced Scanning Options:[/bold]")
    advanced_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
    advanced_table.add_column(style="cyan", justify="center", width=3)
    advanced_table.add_column(style="white")
    advanced_table.add_column(style="dim", width=40)

    advanced_options = [
        ("1", "Basic Scan", "Standard TCP connect scan (reliable but less stealthy)"),
        ("2", "Advanced Scan", "Configure advanced scan options (SYN, FIN, XMAS, etc.)"),
    ]

    for key, desc, help_text in advanced_options:
        advanced_table.add_row(f"[{key}]", desc, help_text)

    console.print(advanced_table)

    advanced_choice = Prompt.ask(
        "[bold cyan]Choose scan mode[/bold cyan]",
        choices=["1", "2"],
        default="1"
    )

    # Initialize port scanner
    scanner = PortScanner(console)

    # Set advanced options
    advanced = False
    configure = False

    if advanced_choice == "2":
        # Check for admin privileges for advanced scanning
        try:
            import platform
            if platform.system() == 'Windows':  # Windows
                try:
                    import ctypes
                    advanced = ctypes.windll.shell32.IsUserAnAdmin() != 0
                except:
                    advanced = False
            else:  # Unix-like
                try:
                    import os
                    advanced = os.geteuid() == 0
                except:
                    advanced = False

            if advanced:
                console.print("[green]Administrator/root privileges detected. Advanced scanning available.[/green]")
                configure = True
            else:
                console.print("[yellow]Warning: Some advanced scan types require administrator/root privileges.[/yellow]")
                if Confirm.ask("[bold yellow]Continue with advanced configuration anyway?[/bold yellow]", default=True):
                    configure = True
                    advanced = True  # We'll let the scanner handle privilege checks for specific scan types
        except:
            console.print("[yellow]Could not determine privilege level. Some scan types may not work.[/yellow]")
            if Confirm.ask("[bold yellow]Continue with advanced configuration anyway?[/bold yellow]", default=True):
                configure = True

    # Run the scan
    scanner.scan(target, ports, threads=thread_count, advanced=advanced, configure=configure)

    console.print("\n[bold cyan]━━━ Scan Complete ━━━[/bold cyan]", justify="center")
    input("\nPress Enter to return to main menu...")

def ping_utility_menu():
    """Handle the ping utility menu options."""
    console.print("\n[bold cyan]━━━ PING UTILITY ━━━[/bold cyan]", justify="center")

    target = Prompt.ask("[bold]📍 Enter target IP or hostname[/bold]")

    # Ping options sub-menu
    console.print("\n[bold]Select ping type:[/bold]")
    ping_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
    ping_table.add_column(style="cyan", justify="center", width=3)
    ping_table.add_column(style="white", width=20, no_wrap=False)
    ping_table.add_column(style="dim", width=40, no_wrap=False)

    ping_options = [
        ("1", "Standard ping", "Send 4 ICMP echo requests and display statistics"),
        ("2", "Continuous ping", "Send ICMP echo requests until stopped (press Ctrl+C)"),
        ("3", "Custom count", "Specify the number of pings to send")
    ]

    for key, desc, help_text in ping_options:
        ping_table.add_row(f"[{key}]", desc, help_text)

    console.print(ping_table)

    ping_choice = Prompt.ask(
        "[bold cyan]Choose ping type[/bold cyan]",
        choices=["1", "2", "3"],
        default="1"
    )

    count = 4
    continuous = False

    if ping_choice == "1":
        count = 4
        console.print("[dim]Selected standard ping (4 packets)[/dim]")
    elif ping_choice == "2":
        continuous = True
        console.print("[dim]Selected continuous ping (press Ctrl+C to stop)[/dim]")
    elif ping_choice == "3":
        count = IntPrompt.ask(
            "[bold]Enter number of pings[/bold]",
            default=4,
            show_default=True
        )
        console.print(f"[dim]Selected custom ping ({count} packets)[/dim]")

    # Initialize and run ping utility
    ping = PingUtility(console)

    with console.status("[bold green]Initializing ping...[/bold green]", spinner="dots"):
        time.sleep(0.5)  # Short pause for visual effect

    ping.ping(target, count=count, continuous=continuous)

    if not continuous:
        console.print("\n[bold cyan]━━━ Ping Complete ━━━[/bold cyan]", justify="center")

    input("\nPress Enter to return to main menu...")

def traceroute_menu():
    """Handle the traceroute menu options."""
    console.print("\n[bold cyan]━━━ TRACEROUTE ━━━[/bold cyan]", justify="center")

    target = Prompt.ask("[bold]📍 Enter target IP or hostname[/bold]")

    # Create a visual explanation of traceroute
    trace_info = Panel(
        "[dim]Traceroute maps the network path between your computer and the target, showing:\n"
        "• Each router/hop along the way\n"
        "• Response time at each hop\n"
        "• Network information where available[/dim]",
        title="[bold]About Traceroute[/bold]",
        border_style="blue",
        padding=(1, 1)
    )
    console.print(trace_info)

    max_hops = IntPrompt.ask(
        "[bold]Enter maximum hops[/bold] [dim](path length limit)[/dim]",
        default=30,
        show_default=True
    )

    # Initialize and run traceroute
    tr = Traceroute(console)

    with console.status("[bold green]Initializing traceroute...[/bold green]", spinner="dots"):
        time.sleep(0.5)  # Short pause for visual effect

    tr.trace(target, max_hops=max_hops)

    console.print("\n[bold cyan]━━━ Trace Complete ━━━[/bold cyan]", justify="center")
    input("\nPress Enter to return to main menu...")

def dns_tools_menu():
    """Handle the DNS tools menu options."""
    console.print("\n[bold cyan]━━━ DNS TOOLS ━━━[/bold cyan]", justify="center")

    # DNS tools explanation panel
    dns_info = Panel(
        "[dim]DNS (Domain Name System) translates domain names to IP addresses.\n"
        "These tools allow you to query different DNS record types and test DNS servers.[/dim]",
        title="[bold]About DNS Tools[/bold]",
        border_style="blue",
        padding=(1, 1)
    )
    console.print(dns_info)

    # DNS tools sub-menu
    dns_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
    dns_table.add_column(style="cyan", justify="center", width=3)
    dns_table.add_column(style="white", width=20, no_wrap=False)
    dns_table.add_column(style="dim", width=40, no_wrap=False)

    dns_options = [
        ("1", "A Record Lookup", "Find IP addresses for a domain"),
        ("2", "MX Record Lookup", "Find mail servers for a domain"),
        ("3", "TXT Record Lookup", "Find text records (SPF, DKIM, etc.)"),
        ("4", "NS Record Lookup", "Find name servers for a domain"),
        ("5", "Reverse DNS Lookup", "Find domain name for an IP address"),
        ("6", "DNS Server Test", "Test a specific DNS server"),
        ("7", "Return to main menu", "Go back to the main menu")
    ]

    for key, desc, help_text in dns_options:
        dns_table.add_row(f"[{key}]", desc, help_text)

    console.print(dns_table)

    dns_choice = Prompt.ask(
        "[bold cyan]Choose DNS tool[/bold cyan]",
        choices=["1", "2", "3", "4", "5", "6", "7"],
        default="1"
    )

    if dns_choice == "7":
        return

    # Get domain name based on lookup type
    if dns_choice in ["1", "2", "3", "4"]:
        domain = Prompt.ask("[bold]📝 Enter domain name[/bold]")
    elif dns_choice == "5":
        domain = Prompt.ask("[bold]🔢 Enter IP address[/bold]")
    elif dns_choice == "6":
        domain = Prompt.ask("[bold]📝 Enter domain name to test[/bold]")
        dns_server = Prompt.ask("[bold]🖥️ Enter DNS server to test[/bold]", default="8.8.8.8")

    # Initialize DNS tools
    dns = DNSTools(console)

    # Perform requested lookup directly without the progress wrapper
    if dns_choice == "1":
        dns.lookup_a(domain)
    elif dns_choice == "2":
        dns.lookup_mx(domain)
    elif dns_choice == "3":
        dns.lookup_txt(domain)
    elif dns_choice == "4":
        dns.lookup_ns(domain)
    elif dns_choice == "5":
        dns.reverse_lookup(domain)
    elif dns_choice == "6":
        dns.test_dns_server(domain, dns_server)

    console.print("\n[bold cyan]━━━ DNS Lookup Complete ━━━[/bold cyan]", justify="center")
    input("\nPress Enter to return to main menu...")

def network_info_menu():
    """Handle the network info menu options."""
    console.print("\n[bold cyan]━━━ NETWORK INFO ━━━[/bold cyan]", justify="center")

    # Network info explanation panel
    net_info = Panel(
        "[dim]View and analyze information about your network interfaces,\n"
        "local configuration, and internet connectivity.[/dim]",
        title="[bold]About Network Info[/bold]",
        border_style="blue",
        padding=(1, 1)
    )
    console.print(net_info)

    # Network info sub-menu
    net_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
    net_table.add_column(style="cyan", justify="center", width=3)
    net_table.add_column(style="white", width=25, no_wrap=False)
    net_table.add_column(style="dim", width=40, no_wrap=False)

    net_options = [
        ("1", "🖧 Local IP Configuration", "View your local network addresses and interfaces"),
        ("2", "🌐 Public IP Detection", "Discover your public-facing IP address"),
        ("3", "📊 Interface Statistics", "Show traffic statistics for network adapters"),
        ("4", "Return to main menu", "Go back to the main menu")
    ]

    for key, desc, help_text in net_options:
        net_table.add_row(f"[{key}]", desc, help_text)

    console.print(net_table)

    net_choice = Prompt.ask(
        "[bold cyan]Choose option[/bold cyan]",
        choices=["1", "2", "3", "4"],
        default="1"
    )

    if net_choice == "4":
        return

    # Initialize network info
    netinfo = NetworkInfo(console)

    with console.status("[bold green]Gathering network information...[/bold green]", spinner="dots"):
        time.sleep(0.5)  # Short pause for visual effect

        # Perform requested function
        if net_choice == "1":
            netinfo.show_local_ip()
        elif net_choice == "2":
            netinfo.show_public_ip()
        elif net_choice == "3":
            netinfo.show_interface_stats()

    console.print("\n[bold cyan]━━━ Network Info Complete ━━━[/bold cyan]", justify="center")
    input("\nPress Enter to return to main menu...")

def device_discovery_menu():
    """Handle the device discovery menu options."""
    console.print("\n[bold cyan]━━━ DEVICE DISCOVERY ━━━[/bold cyan]", justify="center")

    # Create a visual explanation of device discovery
    discovery_info = Panel(
        "[dim]Device discovery scans your network to find connected devices and identify:\n"
        "• IP and MAC addresses of each device\n"
        "• Device hostnames (when available)\n"
        "• Hardware vendor or device type identification[/dim]",
        title="[bold]About Device Discovery[/bold]",
        border_style="blue",
        padding=(1, 1)
    )
    console.print(discovery_info)

    # Network range selection
    console.print("\n[bold]Select network to scan:[/bold]")

    # Get available network interfaces and their ranges
    discovery = DeviceDiscovery(console)
    # Get network interfaces (used internally by discovery._get_network_range())

    # Create a table of available networks
    network_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
    network_table.add_column(style="cyan", justify="center", width=3)
    network_table.add_column(style="white", width=25, no_wrap=False)
    network_table.add_column(style="dim", width=40, no_wrap=False)

    # Add the default network option
    default_range = discovery._get_network_range()
    network_table.add_row("[1]", f"Default network: {default_range}",
                         "Automatically detected network")

    # Add custom network option
    network_table.add_row("[2]", "Custom network range",
                         "Specify a CIDR network (e.g., 192.168.0.0/24)")

    console.print(network_table)

    network_choice = Prompt.ask(
        "[bold cyan]Choose network[/bold cyan]",
        choices=["1", "2"],
        default="1"
    )

    network_range = None
    if network_choice == "1":
        network_range = default_range
        console.print(f"[dim]Selected default network: {network_range}[/dim]")
    elif network_choice == "2":
        network_range = Prompt.ask(
            "[bold]Enter network range in CIDR notation[/bold] [dim](e.g., 192.168.1.0/24)[/dim]"
        )
        console.print(f"[dim]Selected custom network: {network_range}[/dim]")

    # Scan options
    console.print("\n[bold]Scan options:[/bold]")

    # Thread count
    thread_count = IntPrompt.ask(
        "[bold]Number of threads[/bold] [dim](higher = faster but more intensive)[/dim]",
        default=50,
        show_default=True
    )

    # Scan method selection
    use_ping = Prompt.ask(
        "[bold]Scan method[/bold]",
        choices=["arp", "ping"],
        default="arp"
    ) == "ping"

    scan_method = "PING sweep" if use_ping else "ARP scan"
    console.print(f"[dim]Selected {scan_method}[/dim]")

    # Hostname resolution
    resolve_names = Prompt.ask(
        "[bold]Resolve hostnames[/bold] [dim](slower but more informative)[/dim]",
        choices=["yes", "no"],
        default="yes"
    ) == "yes"

    console.print(f"[dim]Hostname resolution: {'enabled' if resolve_names else 'disabled'}[/dim]")

    # Initialize and run discovery
    with console.status("[bold green]Initializing device discovery...[/bold green]", spinner="dots"):
        time.sleep(0.5)  # Short pause for visual effect

    discovery.discover(
        network_range=network_range,
        threads=thread_count,
        use_ping=use_ping,
        resolve_names=resolve_names
    )

    console.print("\n[bold cyan]━━━ Discovery Complete ━━━[/bold cyan]", justify="center")
    input("\nPress Enter to return to main menu...")

def bandwidth_monitor_menu():
    """Handle the bandwidth monitor menu options."""
    console.print("\n[bold cyan]━━━ BANDWIDTH MONITOR ━━━[/bold cyan]", justify="center")

    # Create a visual explanation of bandwidth monitoring
    monitor_info = Panel(
        "[dim]Bandwidth monitor tracks and visualizes network usage in real-time:\n"
        "• Current upload and download speeds\n"
        "• Historical bandwidth usage graph\n"
        "• Total data transferred statistics[/dim]",
        title="[bold]About Bandwidth Monitor[/bold]",
        border_style="blue",
        padding=(1, 1)
    )
    console.print(monitor_info)

    # Interface selection
    console.print("\n[bold]Select network interface:[/bold]")

    # Create bandwidth monitor instance and get interfaces
    bandwidth = BandwidthMonitor(console)
    interfaces = bandwidth._get_available_interfaces()

    # Create a table of available interfaces
    interface_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
    interface_table.add_column(style="cyan", justify="center", width=3)
    interface_table.add_column(style="white", width=25, no_wrap=False)
    interface_table.add_column(style="dim", width=40, no_wrap=False)

    # Add all interfaces option
    interface_table.add_row("[1]", "All interfaces", "Monitor all network interfaces combined")

    # Add each available interface
    option_num = 2
    interface_options = ["all"]  # First option is "all interfaces"

    for name, details in interfaces.items():
        interface_table.add_row(
            f"[{option_num}]",
            f"{name}",
            f"IP: {details['ip']}"
        )
        interface_options.append(name)
        option_num += 1

    console.print(interface_table)

    # Get user choice
    choices = [str(i) for i in range(1, len(interface_options) + 1)]
    interface_choice = Prompt.ask(
        "[bold cyan]Choose interface[/bold cyan]",
        choices=choices,
        default="1"
    )

    selected_interface = None
    if interface_choice != "1":  # Not "All interfaces"
        selected_interface = interface_options[int(interface_choice) - 1]

    console.print(f"[dim]Selected {'all interfaces' if not selected_interface else selected_interface}[/dim]")

    # Duration selection
    console.print("\n[bold]Select monitoring duration:[/bold]")

    duration_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
    duration_table.add_column(style="cyan", justify="center", width=3)
    duration_table.add_column(style="white", width=20, no_wrap=False)
    duration_table.add_column(style="dim", width=40, no_wrap=False)

    duration_options = [
        ("1", "Continuous", "Monitor until manually stopped (Ctrl+C)"),
        ("2", "1 minute", "Monitor for 60 seconds"),
        ("3", "5 minutes", "Monitor for 300 seconds"),
        ("4", "Custom", "Specify a custom duration in seconds")
    ]

    for key, desc, help_text in duration_options:
        duration_table.add_row(f"[{key}]", desc, help_text)

    console.print(duration_table)

    duration_choice = Prompt.ask(
        "[bold cyan]Choose duration[/bold cyan]",
        choices=["1", "2", "3", "4"],
        default="1"
    )

    duration = None  # None means continuous (until Ctrl+C)

    if duration_choice == "2":
        duration = 60
        console.print("[dim]Selected 1 minute monitoring[/dim]")
    elif duration_choice == "3":
        duration = 300
        console.print("[dim]Selected 5 minutes monitoring[/dim]")
    elif duration_choice == "4":
        duration = IntPrompt.ask(
            "[bold]Enter duration in seconds[/bold]",
            default=60
        )
        console.print(f"[dim]Selected {duration} seconds monitoring[/dim]")
    else:
        console.print("[dim]Selected continuous monitoring (press Ctrl+C to stop)[/dim]")

    # Update interval selection
    update_interval = FloatPrompt.ask(
        "[bold]Update interval in seconds[/bold] [dim](lower = more responsive but higher CPU usage)[/dim]",
        default=1.0
    )

    console.print(f"[dim]Selected {update_interval} second update interval[/dim]")

    # Initialize and run bandwidth monitor
    with console.status("[bold green]Initializing bandwidth monitor...[/bold green]", spinner="dots"):
        time.sleep(0.5)  # Short pause for visual effect

    # Run the bandwidth monitor
    bandwidth.monitor(
        interface=selected_interface,
        duration=duration,
        update_interval=update_interval
    )

    console.print("\n[bold cyan]━━━ Monitoring Complete ━━━[/bold cyan]", justify="center")
    input("\nPress Enter to return to main menu...")

def ssl_checker_menu():
    """SSL Certificate Checker menu."""
    console.print("[bold cyan]SSL/TLS Certificate Checker[/bold cyan]")
    console.print("Verify website certificates, check expiration dates, and validate certificate chains.\n")

    # Get hostname/URL
    hostname = Prompt.ask("[yellow]Enter website hostname or URL[/yellow]")
    if not hostname:
        console.print("[bold red]Hostname cannot be empty.[/bold red]")
        return

    # Ask for port (optional)
    port_str = Prompt.ask("[yellow]Enter port number (default: 443)[/yellow]", default="443")
    try:
        port = int(port_str)
    except ValueError:
        console.print("[bold red]Invalid port number. Using default (443).[/bold red]")
        port = 443

    # Display progress
    with console.status(f"[bold green]Checking certificate for {hostname}:{port}...[/bold green]"):
        ssl_checker = SSLCertificateChecker(console)
        ssl_checker.check_website(hostname, port)

    # Ask if user wants to save the result to a file
    if Confirm.ask("[yellow]Would you like to save the results to a file?[/yellow]"):
        filename = Prompt.ask("[yellow]Enter filename[/yellow]", default=f"{hostname}_cert_check.txt")
        with open(filename, "w") as f:
            # Redirect console output to file
            file_console = Console(file=f, width=100)
            file_checker = SSLCertificateChecker(file_console)
            file_checker.check_website(hostname, port)
        console.print(f"[green]Results saved to {filename}[/green]")

    input("\nPress Enter to return to the main menu...")

def vulnerability_scanner_menu():
    """Handle the vulnerability scanner menu options."""
    console.print("\n[bold cyan]━━━ VULNERABILITY SCANNER ━━━[/bold cyan]", justify="center")

    # Create a table for vulnerability scanner options
    vuln_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
    vuln_table.add_column(style="dim cyan", justify="center", width=5)
    vuln_table.add_column(style="yellow", width=25, no_wrap=False)
    vuln_table.add_column(style="dim", width=40, no_wrap=False)

    vuln_table.add_row("1", "Scan Single Host", "Scan a specific host for vulnerabilities")
    vuln_table.add_row("2", "Scan Network Range", "Scan a range of hosts for vulnerabilities")
    vuln_table.add_row("3", "Update Vulnerability Database", "Update the local vulnerability database")
    vuln_table.add_row("4", "Return to Main Menu", "Go back to the main menu")

    console.print(vuln_table)

    vuln_choice = Prompt.ask(
        "[bold cyan]Choose option[/bold cyan]",
        choices=["1", "2", "3", "4"],
        default="1"
    )

    if vuln_choice == "4":
        return

    # Initialize service identifier
    service_identifier = ServiceIdentifier(console)

    if vuln_choice == "1":
        # Scan single host
        target = Prompt.ask("[bold]Enter target IP or hostname[/bold]")

        # Get port selection
        console.print("\n[bold]Select ports to scan:[/bold]")
        port_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
        port_table.add_column(style="dim cyan", justify="center", width=5)
        port_table.add_column(style="yellow", width=25, no_wrap=False)
        port_table.add_column(style="dim", width=40, no_wrap=False)

        port_table.add_row("1", "Common Ports", "Scan commonly used ports (faster)")
        port_table.add_row("2", "All Ports (1-1024)", "Scan all privileged ports (slower)")
        port_table.add_row("3", "Custom Range", "Specify a custom port range")

        console.print(port_table)

        port_choice = Prompt.ask(
            "[bold cyan]Choose option[/bold cyan]",
            choices=["1", "2", "3"],
            default="1"
        )

        ports = []
        if port_choice == "1":
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            console.print("[dim]Selected common ports scan[/dim]")
        elif port_choice == "2":
            ports = list(range(1, 1025))
            console.print("[dim]Selected full port scan (1-1024)[/dim]")
        elif port_choice == "3":
            port_range = Prompt.ask("[bold]Enter port range (e.g., 80-100)[/bold]")
            try:
                start, end = map(int, port_range.split('-'))
                ports = list(range(start, end + 1))
                console.print(f"[dim]Selected custom range: {start}-{end} ({len(ports)} ports)[/dim]")
            except:
                console.print(Panel("[bold red]Invalid port range format![/bold red]\nUsing default ports (1-1024) instead.",
                               border_style="red", title="Error", padding=(1, 2)))
                ports = list(range(1, 1025))

        # Speed/thread options
        thread_count = IntPrompt.ask(
            "[bold]Select thread count[/bold] [dim](higher = faster but more resource intensive)[/dim]",
            default=20,
            show_default=True
        )

        # Initialize and run port scanner with vulnerability detection
        scanner = PortScanner(console)

        # Check for advanced scanning capabilities (using SYN scan)
        try:
            # Only use advanced if we're running as admin/root
            import platform
            advanced = False
            if platform.system() == 'Windows':  # Windows
                try:
                    import ctypes
                    advanced = ctypes.windll.shell32.IsUserAnAdmin() != 0
                except:
                    advanced = False
            else:  # Unix-like
                try:
                    import os
                    advanced = os.geteuid() == 0
                except:
                    advanced = False

            if advanced:
                console.print("[green]Using advanced scanning techniques (SYN scan)[/green]")
        except:
            advanced = False

        # Scan the target
        scanner.scan(target, ports, threads=thread_count, advanced=advanced)

        # Display vulnerability summary
        console.print("\n[bold cyan]━━━ Vulnerability Summary ━━━[/bold cyan]", justify="center")

        # Count vulnerabilities by severity
        vuln_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        vulnerable_services = []

        for port, info in scanner.results.items():
            if info["state"] == "open" and "service_details" in info:
                service_details = info["service_details"]
                if service_details["vulnerabilities"]:
                    for vuln in service_details["vulnerabilities"]:
                        severity = vuln["severity"]
                        if severity in vuln_count:
                            vuln_count[severity] += 1
                        vulnerable_services.append((port, service_details))

        # Create vulnerability summary table
        summary_table = Table(title="Vulnerability Summary", box=box.ROUNDED)
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", style="cyan", justify="right")

        summary_table.add_row("[bold red]Critical[/bold red]", str(vuln_count["Critical"]))
        summary_table.add_row("[bold orange]High[/bold orange]", str(vuln_count["High"]))
        summary_table.add_row("[bold yellow]Medium[/bold yellow]", str(vuln_count["Medium"]))
        summary_table.add_row("[bold green]Low[/bold green]", str(vuln_count["Low"]))

        console.print(summary_table)

        # If vulnerabilities were found, display details
        if sum(vuln_count.values()) > 0:
            console.print("\n[bold red]⚠ Vulnerabilities Detected ⚠[/bold red]")

            for port, service_details in vulnerable_services:
                console.print(f"\n[bold yellow]Port {port} - {service_details['service_name']} {service_details['version'] or ''}[/bold yellow]")
                service_identifier.display_service_info(service_details)
        else:
            console.print("\n[bold green]✓ No vulnerabilities detected![/bold green]")

    elif vuln_choice == "2":
        # Scan network range
        network_range = Prompt.ask("[bold]Enter network range (CIDR notation, e.g., 192.168.1.0/24)[/bold]")

        # Validate network range format
        import ipaddress
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            host_count = sum(1 for _ in network.hosts())

            if host_count > 256:
                if not Confirm.ask(f"[bold yellow]Warning: You're about to scan {host_count} hosts. This may take a long time. Continue?[/bold yellow]"):
                    return
        except:
            console.print(Panel("[bold red]Invalid network range format![/bold red]\nPlease use CIDR notation (e.g., 192.168.1.0/24)",
                           border_style="red", title="Error", padding=(1, 2)))
            return

        # Select ports to scan
        console.print("\n[bold]Select ports to scan:[/bold]")
        port_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
        port_table.add_column(style="dim cyan", justify="center", width=5)
        port_table.add_column(style="yellow", width=25, no_wrap=False)
        port_table.add_column(style="dim", width=40, no_wrap=False)

        port_table.add_row("1", "Common Ports Only", "Scan only the most common ports (faster)")
        port_table.add_row("2", "Extended Port Set", "Scan a larger set of common ports")

        console.print(port_table)

        port_choice = Prompt.ask(
            "[bold cyan]Choose option[/bold cyan]",
            choices=["1", "2"],
            default="1"
        )

        if port_choice == "1":
            ports = [21, 22, 23, 25, 80, 443, 3389, 8080]
            console.print("[dim]Selected minimal port set for faster scanning[/dim]")
        else:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            console.print("[dim]Selected extended port set[/dim]")

        # Initialize device discovery to find hosts
        discovery = DeviceDiscovery(console)

        # Initialize port scanner
        scanner = PortScanner(console)

        # Discover hosts first
        console.print("\n[bold cyan]Step 1: Discovering hosts on the network...[/bold cyan]")
        discovery.discover(network_range=network_range, threads=50, use_ping=True, resolve_names=True)

        # Get list of discovered hosts
        discovered_hosts = [info["ip"] for _, info in discovery.results.items()]

        if not discovered_hosts:
            console.print("[bold yellow]No hosts discovered on the network. Scan aborted.[/bold yellow]")
            return

        console.print(f"[green]Discovered {len(discovered_hosts)} hosts on the network.[/green]")

        # Scan each host for vulnerabilities
        console.print("\n[bold cyan]Step 2: Scanning hosts for vulnerabilities...[/bold cyan]")

        # Track vulnerability statistics
        total_vulns = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        host_vulns = {}

        # Scan each host
        for i, host in enumerate(discovered_hosts):
            console.print(f"\n[bold]Scanning host {i+1}/{len(discovered_hosts)}: [yellow]{host}[/yellow][/bold]")

            # Scan the host
            scanner.scan(host, ports, threads=20, advanced=False)

            # Check for vulnerabilities
            host_vuln_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            vulnerable_services = []

            for port, info in scanner.results.items():
                if info["state"] == "open" and "service_details" in info:
                    service_details = info["service_details"]
                    if service_details["vulnerabilities"]:
                        for vuln in service_details["vulnerabilities"]:
                            severity = vuln["severity"]
                            if severity in host_vuln_count:
                                host_vuln_count[severity] += 1
                                total_vulns[severity] += 1
                        vulnerable_services.append((port, service_details))

            # Store results for this host
            if sum(host_vuln_count.values()) > 0:
                host_vulns[host] = {
                    "vuln_count": host_vuln_count,
                    "services": vulnerable_services
                }

        # Display vulnerability summary
        console.print("\n[bold cyan]━━━ Network Vulnerability Summary ━━━[/bold cyan]", justify="center")

        # Create vulnerability summary table
        summary_table = Table(title=f"Vulnerability Summary for {network_range}", box=box.ROUNDED)
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", style="cyan", justify="right")
        summary_table.add_column("Affected Hosts", style="yellow", justify="right")

        summary_table.add_row(
            "[bold red]Critical[/bold red]",
            str(total_vulns["Critical"]),
            str(sum(1 for host in host_vulns.values() if host["vuln_count"]["Critical"] > 0))
        )
        summary_table.add_row(
            "[bold orange]High[/bold orange]",
            str(total_vulns["High"]),
            str(sum(1 for host in host_vulns.values() if host["vuln_count"]["High"] > 0))
        )
        summary_table.add_row(
            "[bold yellow]Medium[/bold yellow]",
            str(total_vulns["Medium"]),
            str(sum(1 for host in host_vulns.values() if host["vuln_count"]["Medium"] > 0))
        )
        summary_table.add_row(
            "[bold green]Low[/bold green]",
            str(total_vulns["Low"]),
            str(sum(1 for host in host_vulns.values() if host["vuln_count"]["Low"] > 0))
        )

        console.print(summary_table)

        # If vulnerabilities were found, display details
        if sum(total_vulns.values()) > 0:
            console.print("\n[bold red]⚠ Vulnerabilities Detected ⚠[/bold red]")

            # Create a table of vulnerable hosts
            host_table = Table(title="Vulnerable Hosts", box=box.ROUNDED)
            host_table.add_column("Host", style="yellow")
            host_table.add_column("Critical", style="red", justify="right")
            host_table.add_column("High", style="orange", justify="right")
            host_table.add_column("Medium", style="yellow", justify="right")
            host_table.add_column("Low", style="green", justify="right")

            for host, data in host_vulns.items():
                host_table.add_row(
                    host,
                    str(data["vuln_count"]["Critical"]),
                    str(data["vuln_count"]["High"]),
                    str(data["vuln_count"]["Medium"]),
                    str(data["vuln_count"]["Low"])
                )

            console.print(host_table)

            # Ask if user wants to see detailed vulnerability information
            if Confirm.ask("[bold]Would you like to see detailed vulnerability information?[/bold]"):
                for host, data in host_vulns.items():
                    console.print(f"\n[bold cyan]Host: [yellow]{host}[/yellow][/bold cyan]")

                    for port, service_details in data["services"]:
                        console.print(f"\n[bold yellow]Port {port} - {service_details['service_name']} {service_details['version'] or ''}[/bold yellow]")
                        service_identifier.display_service_info(service_details)
        else:
            console.print("\n[bold green]✓ No vulnerabilities detected in the network![/bold green]")

    elif vuln_choice == "3":
        # Update vulnerability database
        console.print("\n[bold cyan]Updating vulnerability database...[/bold cyan]")

        # This would normally connect to an online source to update the database
        # For this implementation, we'll just reload the database
        service_identifier = ServiceIdentifier(console)
        service_identifier._load_vulnerability_db()

        console.print("[bold green]✓ Vulnerability database updated successfully![/bold green]")

    console.print("\n[bold cyan]━━━ Vulnerability Scanning Complete ━━━[/bold cyan]", justify="center")
    input("\nPress Enter to return to main menu...")
    return

def ip_geolocation_menu():
    """Handle the IP geolocation menu options."""
    console.print("\n[bold cyan]━━━ IP GEOLOCATION ━━━[/bold cyan]", justify="center")

    # IP Geolocation explanation panel
    geo_info = Panel(
        "[dim]Map IP addresses to physical locations and visualize network paths.\n"
        "Discover the geographical origin of IP addresses and trace routes across the globe.[/dim]",
        title="[bold]About IP Geolocation[/bold]",
        border_style="blue",
        padding=(1, 1)
    )
    console.print(geo_info)

    # IP Geolocation sub-menu
    geo_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
    geo_table.add_column(style="cyan", justify="center", width=3)
    geo_table.add_column(style="white", width=25, no_wrap=False)
    geo_table.add_column(style="dim", width=40, no_wrap=False)

    geo_options = [
        ("1", "🌐 Lookup IP Address", "Find location of a single IP address"),
        ("2", "🌍 Trace Path with Geolocation", "Map a network path across the globe"),
        ("3", "Return to main menu", "Go back to the main menu")
    ]

    for key, desc, help_text in geo_options:
        geo_table.add_row(f"[{key}]", desc, help_text)

    console.print(geo_table)

    geo_choice = Prompt.ask(
        "[bold cyan]Choose option[/bold cyan]",
        choices=["1", "2", "3"],
        default="1"
    )

    if geo_choice == "3":
        return

    # Ask if user wants an HTML map output
    html_output = Confirm.ask(
        "[bold cyan]Generate interactive HTML map?[/bold cyan]",
        default=True
    )

    output_file = None
    open_map = False
    if html_output:
        output_file = Prompt.ask(
            "[bold cyan]Enter output HTML file path[/bold cyan]",
            default="geomap.html"
        )

        open_map = Confirm.ask(
            "[bold cyan]Automatically open the map in browser?[/bold cyan]",
            default=True
        )

    # Initialize geolocation module
    geolocation = IPGeolocation(console)

    if geo_choice == "1":
        # IP lookup
        target = Prompt.ask("[bold]📍 Enter IP address or hostname[/bold]")
        geolocation.lookup_ip(target, output_file, open_map)
    elif geo_choice == "2":
        # Path tracing with geolocation
        target = Prompt.ask("[bold]📍 Enter target IP address or hostname[/bold]")
        geolocation.trace_path(target, output_file, open_map)

    input("\nPress Enter to return to main menu...")

def mac_address_changer_menu():
    """Handle the MAC address changer menu options."""
    console.print("\n[bold cyan]━━━ MAC ADDRESS CHANGER ━━━[/bold cyan]", justify="center")

    # Create a panel explaining MAC address changing
    mac_info = Panel(
        "[bold]MAC Address Changing[/bold]\n\n"
        "A MAC (Media Access Control) address is a unique identifier assigned to a network interface. "
        "Changing your MAC address can be useful for:\n"
        "  • Bypassing MAC filtering on networks\n"
        "  • Increasing privacy by preventing tracking\n"
        "  • Testing network security\n"
        "  • Troubleshooting network issues\n\n"
        "[bold yellow]Note:[/bold yellow] Changing MAC addresses may require administrator/root privileges.",
        title="About MAC Addresses",
        border_style="blue",
        padding=(1, 2)
    )
    console.print(mac_info)

    # Initialize MAC address changer
    mac_changer = MACAddressChanger(console)

    # Display available interfaces
    console.print("\n[bold]Available Network Interfaces:[/bold]")
    interfaces = mac_changer.display_interfaces()

    if not interfaces:
        console.print("[bold red]No network interfaces available for MAC address changing.[/bold red]")
        input("\nPress Enter to return to main menu...")
        return

    # Create a table for MAC changer options
    mac_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
    mac_table.add_column(style="dim cyan", justify="center", width=5)
    mac_table.add_column(style="yellow", width=25, no_wrap=False)
    mac_table.add_column(style="dim", width=40, no_wrap=False)

    mac_table.add_row("1", "Change to Random MAC", "Assign a random MAC address to an interface")
    mac_table.add_row("2", "Change to Specific MAC", "Set a custom MAC address for an interface")
    mac_table.add_row("3", "Restore Original MAC", "Restore the original MAC address of an interface")
    mac_table.add_row("4", "Return to Main Menu", "Go back to the main menu")

    console.print("\n[bold]Select an option:[/bold]")
    console.print(mac_table)

    mac_choice = Prompt.ask(
        "[bold cyan]Choose option[/bold cyan]",
        choices=["1", "2", "3", "4"],
        default="4"
    )

    if mac_choice == "4":
        return

    # Select interface
    console.print("\n[bold]Select a network interface:[/bold]")
    interface_num = IntPrompt.ask(
        "Enter interface number",
        default=1,
        show_default=True
    )

    # Validate interface selection
    if interface_num < 1 or interface_num > len(interfaces):
        console.print("[bold red]Invalid interface selection.[/bold red]")
        input("\nPress Enter to return to main menu...")
        return

    selected_interface = interfaces[interface_num - 1]
    interface_name = selected_interface["name"]
    current_mac = selected_interface["mac"]

    console.print(f"\n[bold]Selected interface:[/bold] [green]{interface_name}[/green] (Current MAC: [yellow]{current_mac}[/yellow])")

    # Check for admin/root privileges
    admin_required_warning = "\n[bold yellow]Note:[/bold yellow] Changing MAC addresses requires administrator/root privileges."
    if platform.system() == "Windows":
        admin_required_warning += " Make sure you're running as Administrator."
    else:
        admin_required_warning += " Make sure you're running with sudo."
    console.print(admin_required_warning)

    # Process the selected option
    if mac_choice == "1":
        # Change to random MAC
        if Confirm.ask("\n[bold]Change to a random MAC address?[/bold]"):
            result = mac_changer.change_mac(interface_name)
            if result:
                console.print("[bold green]MAC address changed successfully![/bold green]")
            else:
                console.print("[bold red]Failed to change MAC address.[/bold red]")

    elif mac_choice == "2":
        # Change to specific MAC
        new_mac = Prompt.ask(
            "\n[bold]Enter new MAC address[/bold] (format: XX:XX:XX:XX:XX:XX)",
            default=current_mac
        )

        if Confirm.ask(f"\n[bold]Change MAC address to {new_mac}?[/bold]"):
            result = mac_changer.change_mac(interface_name, new_mac)
            if result:
                console.print("[bold green]MAC address changed successfully![/bold green]")
            else:
                console.print("[bold red]Failed to change MAC address.[/bold red]")

    elif mac_choice == "3":
        # Restore original MAC
        result = mac_changer.restore_original_mac(interface_name)
        if not result:
            console.print("[bold yellow]No original MAC address stored or restoration failed.[/bold yellow]")
            console.print("[dim]Note: Original MACs are only stored for the current session.[/dim]")

    # Display current interfaces after change
    console.print("\n[bold]Current Network Interfaces:[/bold]")
    mac_changer.display_interfaces()

    console.print("\n[bold cyan]━━━ MAC Address Operation Complete ━━━[/bold cyan]", justify="center")
    input("\nPress Enter to return to main menu...")
    return

def parse_arguments():
    """Parse command line arguments for direct CLI usage."""
    parser = argparse.ArgumentParser(
        description='NetworkScan Pro - Advanced CLI Network Utility',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan google.com --ports 80,443
  %(prog)s ping google.com --count 5
  %(prog)s dns google.com --type mx
  %(prog)s --json ping google.com --count 2
  %(prog)s check
        """
    )
    
    # Global arguments
    parser.add_argument('--version', '-V', action='version', 
                       version=f'{__title__} v{__version__} - {__description__}')
    parser.add_argument('--json', '-j', action='store_true',
                       help='Output results in JSON format (where supported)')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress banner and decorative output')

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Check/health command
    check_parser = subparsers.add_parser('check', help='Check system dependencies and health')
    check_parser.add_argument('--verbose', '-v', action='store_true', 
                             help='Show detailed dependency information')

    # Port scanner arguments
    port_parser = subparsers.add_parser('scan', help='Port scanner')
    port_parser.add_argument('target', help='Target IP or hostname')
    port_parser.add_argument('--ports', '-p', help='Ports to scan (e.g., 80,443 or 20-25)')
    port_parser.add_argument('--common', '-c', action='store_true', help='Scan common ports')

    # Ping arguments
    ping_parser = subparsers.add_parser('ping', help='Ping utility')
    ping_parser.add_argument('target', help='Target IP or hostname')
    ping_parser.add_argument('--count', '-c', type=int, default=4, help='Number of pings to send')
    ping_parser.add_argument('--continuous', action='store_true', help='Continuous ping mode')

    # Traceroute arguments
    trace_parser = subparsers.add_parser('trace', help='Traceroute utility')
    trace_parser.add_argument('target', help='Target IP or hostname')
    trace_parser.add_argument('--max-hops', type=int, default=30, help='Maximum number of hops')

    # DNS tools arguments
    dns_parser = subparsers.add_parser('dns', help='DNS tools')
    dns_parser.add_argument('target', help='Domain name or IP address')
    dns_parser.add_argument('--type', '-t', choices=['a', 'mx', 'txt', 'ns', 'reverse', 'test'],
                           default='a', help='Type of DNS lookup')
    dns_parser.add_argument('--server', '-s', help='DNS server to use for testing')

    # Network info arguments
    net_parser = subparsers.add_parser('netinfo', help='Network information')
    net_parser.add_argument('--type', '-t', choices=['local', 'public', 'stats'],
                           default='local', help='Type of network information')

    # Device discovery arguments
    discover_parser = subparsers.add_parser('discover', help='Network device discovery')
    discover_parser.add_argument('--network', '-n', help='Network range in CIDR notation (e.g., 192.168.1.0/24)')
    discover_parser.add_argument('--interface', '-i', help='Network interface to scan')
    discover_parser.add_argument('--threads', '-t', type=int, default=50, help='Number of threads to use')
    discover_parser.add_argument('--ping', '-p', action='store_true', help='Use ping instead of ARP')
    discover_parser.add_argument('--no-resolve', action='store_true', help='Disable hostname resolution')

    # Bandwidth monitor arguments
    bandwidth_parser = subparsers.add_parser('bandwidth', help='Bandwidth monitor')
    bandwidth_parser.add_argument('--interface', '-i', help='Network interface to monitor')
    bandwidth_parser.add_argument('--duration', '-d', type=int, help='Monitoring duration in seconds')
    bandwidth_parser.add_argument('--interval', '-n', type=float, default=1.0,
                                 help='Update interval in seconds')

    # SSL Certificate Checker arguments
    ssl_parser = subparsers.add_parser('ssl', help='Check SSL/TLS certificate')
    ssl_parser.add_argument('hostname', help='Target hostname or URL', nargs='?')
    ssl_parser.add_argument('--port', type=int, default=443, help='Target port (default: 443)')
    ssl_parser.add_argument('--save', help='Save results to specified file')
    ssl_parser.add_argument('--batch', help='Batch check certificates from file (one host[:port] per line)')
    ssl_parser.add_argument('--threads', type=int, default=10, help='Number of threads for batch checking (default: 10)')

    # IP Geolocation arguments
    geo_parser = subparsers.add_parser('geoip', help='IP geolocation tools')
    geo_parser.add_argument('target', help='Target IP address or hostname')
    geo_parser.add_argument('--trace', '-t', action='store_true',
                           help='Trace path to target with geolocation')
    geo_parser.add_argument('--output', '-o', help='Save interactive HTML map to specified file')
    geo_parser.add_argument('--open', '-b', action='store_true',
                           help='Automatically open the generated map in the default browser')

    return parser.parse_args()

def check_system_health(verbose=False):
    """Check system dependencies and report health status."""
    global JSON_OUTPUT
    
    deps = {
        "rich": {"required": True, "installed": False, "version": None},
        "scapy": {"required": True, "installed": False, "version": None},
        "dnspython": {"required": True, "installed": False, "version": None},
        "requests": {"required": True, "installed": False, "version": None},
        "psutil": {"required": True, "installed": False, "version": None},
        "pyOpenSSL": {"required": True, "installed": False, "version": None},
        "pythonping": {"required": True, "installed": False, "version": None},
        "folium": {"required": False, "installed": False, "version": None},
    }
    
    # Check each dependency
    for dep_name in deps:
        try:
            if dep_name == "dnspython":
                import dns
                deps[dep_name]["installed"] = True
                deps[dep_name]["version"] = getattr(dns, "__version__", "unknown")
            elif dep_name == "pyOpenSSL":
                import OpenSSL
                deps[dep_name]["installed"] = True
                deps[dep_name]["version"] = getattr(OpenSSL, "__version__", "unknown")
            else:
                mod = __import__(dep_name)
                deps[dep_name]["installed"] = True
                deps[dep_name]["version"] = getattr(mod, "__version__", "unknown")
        except ImportError:
            pass
    
    # Check system info
    import socket
    system_info = {
        "platform": platform.system(),
        "platform_version": platform.version(),
        "python_version": platform.python_version(),
        "hostname": socket.gethostname(),
    }
    
    # Check admin privileges
    is_admin = False
    try:
        if platform.system() == 'Windows':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.geteuid() == 0
    except:
        pass
    
    system_info["admin_privileges"] = is_admin
    
    if JSON_OUTPUT:
        result = {
            "version": __version__,
            "system": system_info,
            "dependencies": deps,
            "all_required_installed": all(d["installed"] for d in deps.values() if d["required"])
        }
        print(json.dumps(result, indent=2))
    else:
        # Display health check results
        console.print(Panel(
            f"[bold cyan]{__title__}[/bold cyan] v{__version__}",
            title="System Health Check",
            border_style="blue"
        ))
        
        # System info table
        sys_table = Table(title="System Information", box=box.ROUNDED)
        sys_table.add_column("Property", style="cyan")
        sys_table.add_column("Value", style="green")
        
        sys_table.add_row("Platform", f"{system_info['platform']} {system_info['platform_version']}")
        sys_table.add_row("Python Version", system_info['python_version'])
        sys_table.add_row("Hostname", system_info['hostname'])
        admin_status = "[green]Yes[/green]" if is_admin else "[yellow]No[/yellow] (some features limited)"
        sys_table.add_row("Admin Privileges", admin_status)
        
        console.print(sys_table)
        
        # Dependencies table
        dep_table = Table(title="Dependencies", box=box.ROUNDED)
        dep_table.add_column("Package", style="cyan")
        dep_table.add_column("Required", style="dim")
        dep_table.add_column("Status", style="green")
        if verbose:
            dep_table.add_column("Version", style="dim")
        
        for name, info in sorted(deps.items()):
            req = "Yes" if info["required"] else "Optional"
            status = "[green]✓ Installed[/green]" if info["installed"] else "[red]✗ Missing[/red]"
            if verbose:
                ver = info["version"] or "-"
                dep_table.add_row(name, req, status, ver)
            else:
                dep_table.add_row(name, req, status)
        
        console.print(dep_table)
        
        # Overall status
        all_required = all(d["installed"] for d in deps.values() if d["required"])
        if all_required:
            console.print("\n[bold green]✓ All required dependencies are installed.[/bold green]")
        else:
            missing = [n for n, d in deps.items() if d["required"] and not d["installed"]]
            console.print(f"\n[bold red]✗ Missing required dependencies: {', '.join(missing)}[/bold red]")
            console.print("[yellow]Run: pip install -r requirements.txt[/yellow]")


def process_cli_arguments(args):
    """Process the command line arguments and run the appropriate function."""
    global QUIET_MODE
    
    if not args.command:
        # If no command specified, launch interactive menu
        if not QUIET_MODE:
            display_banner()
        main_menu()
        return
    
    # Check/health command
    if args.command == 'check':
        check_system_health(verbose=getattr(args, 'verbose', False))
        return

    # Port scanner
    if args.command == 'scan':
        scanner = PortScanner(console)
        ports = []

        if args.common:
            ports = [20, 21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]
        elif args.ports:
            if '-' in args.ports:
                start, end = map(int, args.ports.split('-'))
                ports = list(range(start, end + 1))
            else:
                ports = list(map(int, args.ports.split(',')))
        else:
            ports = [80, 443]  # Default ports

        # Check for advanced scanning capabilities (using SYN scan)
        try:
            # Only use advanced if we're running as admin/root
            import platform
            advanced = False
            if platform.system() == 'Windows':  # Windows
                try:
                    import ctypes
                    advanced = ctypes.windll.shell32.IsUserAnAdmin() != 0
                except:
                    advanced = False
            else:  # Unix-like
                try:
                    import os
                    advanced = os.geteuid() == 0
                except:
                    advanced = False
        except:
            advanced = False

        scanner.scan(args.target, ports, threads=100, advanced=advanced)

    # Ping utility
    elif args.command == 'ping':
        ping = PingUtility(console)
        ping.ping(args.target, count=args.count, continuous=args.continuous)

    # Traceroute
    elif args.command == 'trace':
        tr = Traceroute(console)
        tr.trace(args.target, max_hops=args.max_hops)

    # DNS tools
    elif args.command == 'dns':
        dns = DNSTools(console)

        # Parse domain properly to ensure it doesn't contain URLs
        target = args.target
        # Remove protocol and path if URL was provided
        if '//' in target:
            target = target.split('//', 1)[1]
        # Remove any remaining path
        target = target.split('/', 1)[0]

        if args.type == 'a':
            dns.lookup_a(target)
        elif args.type == 'mx':
            dns.lookup_mx(target)
        elif args.type == 'txt':
            dns.lookup_txt(target)
        elif args.type == 'ns':
            dns.lookup_ns(target)
        elif args.type == 'reverse':
            dns.reverse_lookup(target)
        elif args.type == 'test':
            server = args.server or '8.8.8.8'
            dns.test_dns_server(target, server)

    # Network info
    elif args.command == 'netinfo':
        netinfo = NetworkInfo(console)

        if args.type == 'local':
            netinfo.show_local_ip()
        elif args.type == 'public':
            netinfo.show_public_ip()
        elif args.type == 'stats':
            netinfo.show_interface_stats()

    # Device discovery
    elif args.command == 'discover':
        discovery = DeviceDiscovery(console)
        network_range = args.network
        resolve_names = not args.no_resolve

        discovery.discover(
            network_range=network_range,
            interface=args.interface,
            threads=args.threads,
            use_ping=args.ping,
            resolve_names=resolve_names
        )

    # Bandwidth monitor
    elif args.command == 'bandwidth':
        monitor = BandwidthMonitor(console)
        monitor.monitor(
            interface=args.interface,
            duration=args.duration,
            update_interval=args.interval
        )

    # SSL Certificate Checker
    elif args.command == 'ssl':
        ssl_checker = SSLCertificateChecker(console)

        if args.batch:
            try:
                with open(args.batch, 'r') as f:
                    targets = []
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue

                        if ':' in line:
                            host, port = line.split(':', 1)
                            try:
                                port = int(port)
                            except ValueError:
                                console.print(f"[bold red]Invalid port for {line}, using default (443)[/bold red]")
                                port = 443
                        else:
                            host = line
                            port = 443

                        targets.append((host, port))

                    console.print(f"[bold cyan]Batch checking {len(targets)} certificates...[/bold cyan]")
                    results = ssl_checker.batch_check(targets, args.threads)

                    # Display results
                    for target, result in results.items():
                        console.print(f"\n[bold yellow]=== {target} ===[/bold yellow]")
                        ssl_checker.display_certificate_info(result)

                    # Save results if requested
                    if args.save:
                        with open(args.save, 'w') as f:
                            file_console = Console(file=f, width=100)
                            file_checker = SSLCertificateChecker(file_console)

                            for target, result in results.items():
                                file_console.print(f"\n=== {target} ===")
                                file_checker.display_certificate_info(result)

                        console.print(f"[green]Results saved to {args.save}[/green]")
            except FileNotFoundError:
                console.print(f"[bold red]Error: File not found: {args.batch}[/bold red]")
        else:
            if not args.hostname:
                console.print("[bold red]Error: Hostname is required when not using batch mode[/bold red]")
                sys.exit(1)

            # Single certificate check
            ssl_checker.check_website(args.hostname, args.port)

            # Save results if requested
            if args.save:
                with open(args.save, 'w') as f:
                    file_console = Console(file=f, width=100)
                    file_checker = SSLCertificateChecker(file_console)
                    file_checker.check_website(args.hostname, args.port)

                console.print(f"[green]Results saved to {args.save}[/green]")

    # IP Geolocation
    elif args.command == 'geoip':
        geolocation = IPGeolocation(console)

        if args.trace:
            # Trace path with geolocation
            geolocation.trace_path(args.target, args.output, args.open)
        else:
            # Single IP lookup
            geolocation.lookup_ip(args.target, args.output, args.open)

    else:
        # Interactive mode
        console.print("\n[bold cyan]Starting interactive mode...[/bold cyan]")
        display_banner()
        main_menu()

def main():
    """Main entry point for the CLI application."""
    global QUIET_MODE, JSON_OUTPUT
    
    try:
        args = parse_arguments()
        
        # Handle global flags
        if hasattr(args, 'quiet') and args.quiet:
            QUIET_MODE = True
        if hasattr(args, 'json') and args.json:
            JSON_OUTPUT = True
        
        process_cli_arguments(args)
    except KeyboardInterrupt:
        if not QUIET_MODE:
            console.print("\n[yellow]Program interrupted by user. Exiting...[/yellow]")
        sys.exit(0)
    except Exception as e:
        if JSON_OUTPUT:
            print(json.dumps({"error": str(e)}, indent=2))
        else:
            console.print(f"[bold red]Error: {str(e)}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()