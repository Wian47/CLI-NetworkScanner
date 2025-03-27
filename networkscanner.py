#!/usr/bin/env python3
import argparse
import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich.table import Table
from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn
from rich import box

from modules.port_scanner import PortScanner
from modules.ping_utility import PingUtility
from modules.traceroute import Traceroute
from modules.dns_tools import DNSTools
from modules.network_info import NetworkInfo
from modules.device_discovery import DeviceDiscovery

VERSION = "1.0.0"
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
            ("q", "🚪 Exit", "Quit the application")
        ]
        
        # Create a stylized menu table
        menu_table = Table(show_header=False, box=box.ROUNDED, expand=True, border_style="cyan")
        menu_table.add_column(style="dim cyan", justify="center", width=5)
        menu_table.add_column(style="bold white", justify="left")
        menu_table.add_column(style="dim", justify="left")
        
        for key, desc, help_text in menu_items:
            menu_table.add_row(f"[{key}]", desc, help_text)
            
        console.print(menu_table)
        
        choice = Prompt.ask(
            "\n[bold cyan]Enter your choice[/bold cyan]", 
            choices=["1", "2", "3", "4", "5", "6", "q"], 
            default="q",
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
        elif choice == "q":
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
    port_table.add_column(style="white")
    port_table.add_column(style="dim", width=30)
    
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
    
    # Initialize and run port scanner
    scanner = PortScanner(console)
    
    # Check for advanced scanning capabilities (using SYN scan)
    try:
        # Only use advanced if we're running as admin/root
        import os
        advanced = False
        if os.name == 'nt':  # Windows
            try:
                import ctypes
                advanced = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                advanced = False
        else:  # Unix-like
            advanced = os.geteuid() == 0
            
        if advanced:
            console.print("[green]Using advanced scanning techniques (SYN scan)[/green]")
    except:
        advanced = False
        
    scanner.scan(target, ports, threads=thread_count, advanced=advanced)
    
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
    ping_table.add_column(style="white", no_wrap=True)
    ping_table.add_column(style="dim")
    
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
    dns_table.add_column(style="white", no_wrap=True)
    dns_table.add_column(style="dim")
    
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
        console.print(f"[dim]Looking up records for {domain}...[/dim]")
    elif dns_choice == "5":
        domain = Prompt.ask("[bold]🔢 Enter IP address[/bold]")
        console.print(f"[dim]Performing reverse lookup for {domain}...[/dim]")
    elif dns_choice == "6":
        domain = Prompt.ask("[bold]📝 Enter domain name to test[/bold]")
        dns_server = Prompt.ask("[bold]🖥️ Enter DNS server to test[/bold]", default="8.8.8.8")
        console.print(f"[dim]Testing {dns_server} with {domain}...[/dim]")
    
    # Initialize DNS tools
    dns = DNSTools(console)
    
    with console.status("[bold green]Performing DNS lookup...[/bold green]", spinner="dots"):
        time.sleep(0.5)  # Short pause for visual effect
        
        # Perform requested lookup
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
    net_table.add_column(style="white", no_wrap=True)
    net_table.add_column(style="dim")
    
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
    interfaces = discovery._get_network_interfaces()
    
    # Create a table of available networks
    network_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
    network_table.add_column(style="cyan", justify="center", width=3)
    network_table.add_column(style="white")
    network_table.add_column(style="dim")
    
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

def parse_arguments():
    """Parse command line arguments for direct CLI usage."""
    parser = argparse.ArgumentParser(description='NetworkScan Pro - Advanced CLI Network Utility')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
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
    
    return parser.parse_args()

def process_cli_arguments(args):
    """Process the command line arguments and run the appropriate function."""
    if not args.command:
        # If no command specified, launch interactive menu
        display_banner()
        main_menu()
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
            import os
            advanced = False
            if os.name == 'nt':  # Windows
                try:
                    import ctypes
                    advanced = ctypes.windll.shell32.IsUserAnAdmin() != 0
                except:
                    advanced = False
            else:  # Unix-like
                advanced = os.geteuid() == 0
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
        
        if args.type == 'a':
            dns.lookup_a(args.target)
        elif args.type == 'mx':
            dns.lookup_mx(args.target)
        elif args.type == 'txt':
            dns.lookup_txt(args.target)
        elif args.type == 'ns':
            dns.lookup_ns(args.target)
        elif args.type == 'reverse':
            dns.reverse_lookup(args.target)
        elif args.type == 'test':
            server = args.server or '8.8.8.8'
            dns.test_dns_server(args.target, server)
            
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

if __name__ == "__main__":
    try:
        args = parse_arguments()
        process_cli_arguments(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Program interrupted by user. Exiting...[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
        sys.exit(1) 