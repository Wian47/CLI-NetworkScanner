#!/usr/bin/env python3
import argparse
import sys
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich.table import Table
from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn

from modules.port_scanner import PortScanner
from modules.ping_utility import PingUtility
from modules.traceroute import Traceroute
from modules.dns_tools import DNSTools
from modules.network_info import NetworkInfo

VERSION = "1.0.0"
console = Console()

def display_banner():
    """Display ASCII art banner with tool name and version."""
    banner = """
    ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ ███████╗██║     ███████║██╔██╗ ██║
    ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ ╚════██║██║     ██╔══██║██║╚██╗██║
    ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                               PRO                                                    
    """
    console.print(Panel(banner, subtitle=f"v{VERSION}", subtitle_align="right", border_style="blue"))
    console.print("[bold blue]Advanced CLI Network Utility with Rich UI/UX[/bold blue]", justify="center")
    console.print()

def main_menu():
    """Display and handle the main menu options."""
    while True:
        console.print("\n[bold cyan]MAIN MENU[/bold cyan]")
        menu_table = Table(show_header=False, box=None)
        menu_table.add_column(style="green")
        menu_table.add_column(style="white")
        
        menu_items = [
            ("1", "Port Scanner"),
            ("2", "Ping Utility"),
            ("3", "Traceroute"),
            ("4", "DNS Tools"),
            ("5", "Network Info"),
            ("q", "Quit")
        ]
        
        for key, desc in menu_items:
            menu_table.add_row(f"[{key}]", desc)
            
        console.print(menu_table)
        
        choice = Prompt.ask("\nEnter your choice", choices=["1", "2", "3", "4", "5", "q"], default="q")
        
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
        elif choice == "q":
            console.print("[yellow]Thank you for using NetworkScan Pro![/yellow]")
            sys.exit(0)

def port_scanner_menu():
    """Handle the port scanner menu options."""
    console.print("\n[bold cyan]PORT SCANNER[/bold cyan]")
    
    target = Prompt.ask("[bold]Enter target IP or hostname[/bold]")
    
    # Port selection sub-menu
    console.print("\n[bold]Select port scan type:[/bold]")
    port_table = Table(show_header=False, box=None)
    port_table.add_column(style="green")
    port_table.add_column(style="white")
    
    port_options = [
        ("1", "Common ports (20-25, 53, 80, 443, 3306, 3389, 8080)"),
        ("2", "Full scan (1-1024)"),
        ("3", "Custom range")
    ]
    
    for key, desc in port_options:
        port_table.add_row(f"[{key}]", desc)
        
    console.print(port_table)
    
    port_choice = Prompt.ask("Enter your choice", choices=["1", "2", "3"], default="1")
    
    ports = []
    if port_choice == "1":
        ports = [20, 21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]
    elif port_choice == "2":
        ports = list(range(1, 1025))
    elif port_choice == "3":
        port_range = Prompt.ask("[bold]Enter port range (e.g., 80-100)[/bold]")
        try:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
        except:
            console.print("[bold red]Invalid port range. Using default ports (1-1024).[/bold red]")
            ports = list(range(1, 1025))
    
    # Initialize and run port scanner
    scanner = PortScanner(console)
    scanner.scan(target, ports)
    
    input("\nPress Enter to return to main menu...")

def ping_utility_menu():
    """Handle the ping utility menu options."""
    console.print("\n[bold cyan]PING UTILITY[/bold cyan]")
    
    target = Prompt.ask("[bold]Enter target IP or hostname[/bold]")
    
    # Ping options sub-menu
    console.print("\n[bold]Select ping type:[/bold]")
    ping_table = Table(show_header=False, box=None)
    ping_table.add_column(style="green")
    ping_table.add_column(style="white")
    
    ping_options = [
        ("1", "Standard ping (4 packets)"),
        ("2", "Continuous ping (press Ctrl+C to stop)"),
        ("3", "Custom count")
    ]
    
    for key, desc in ping_options:
        ping_table.add_row(f"[{key}]", desc)
        
    console.print(ping_table)
    
    ping_choice = Prompt.ask("Enter your choice", choices=["1", "2", "3"], default="1")
    
    count = 4
    continuous = False
    
    if ping_choice == "1":
        count = 4
    elif ping_choice == "2":
        continuous = True
    elif ping_choice == "3":
        count = IntPrompt.ask("[bold]Enter number of pings[/bold]", default=4)
    
    # Initialize and run ping utility
    ping = PingUtility(console)
    ping.ping(target, count=count, continuous=continuous)
    
    input("\nPress Enter to return to main menu...")

def traceroute_menu():
    """Handle the traceroute menu options."""
    console.print("\n[bold cyan]TRACEROUTE[/bold cyan]")
    
    target = Prompt.ask("[bold]Enter target IP or hostname[/bold]")
    max_hops = IntPrompt.ask("[bold]Enter maximum hops[/bold]", default=30)
    
    # Initialize and run traceroute
    tr = Traceroute(console)
    tr.trace(target, max_hops=max_hops)
    
    input("\nPress Enter to return to main menu...")

def dns_tools_menu():
    """Handle the DNS tools menu options."""
    console.print("\n[bold cyan]DNS TOOLS[/bold cyan]")
    
    # DNS tools sub-menu
    dns_table = Table(show_header=False, box=None)
    dns_table.add_column(style="green")
    dns_table.add_column(style="white")
    
    dns_options = [
        ("1", "A Record Lookup"),
        ("2", "MX Record Lookup"),
        ("3", "TXT Record Lookup"),
        ("4", "NS Record Lookup"),
        ("5", "Reverse DNS Lookup"),
        ("6", "DNS Server Test"),
        ("7", "Return to main menu")
    ]
    
    for key, desc in dns_options:
        dns_table.add_row(f"[{key}]", desc)
        
    console.print(dns_table)
    
    dns_choice = Prompt.ask("Enter your choice", choices=["1", "2", "3", "4", "5", "6", "7"], default="1")
    
    if dns_choice == "7":
        return
    
    # Get domain name based on lookup type
    if dns_choice in ["1", "2", "3", "4"]:
        domain = Prompt.ask("[bold]Enter domain name[/bold]")
    elif dns_choice == "5":
        domain = Prompt.ask("[bold]Enter IP address[/bold]")
    elif dns_choice == "6":
        domain = Prompt.ask("[bold]Enter domain name to test[/bold]")
        dns_server = Prompt.ask("[bold]Enter DNS server to test (default: 8.8.8.8)[/bold]", default="8.8.8.8")
    
    # Initialize DNS tools
    dns = DNSTools(console)
    
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
    
    input("\nPress Enter to return to main menu...")

def network_info_menu():
    """Handle the network info menu options."""
    console.print("\n[bold cyan]NETWORK INFO[/bold cyan]")
    
    # Network info sub-menu
    net_table = Table(show_header=False, box=None)
    net_table.add_column(style="green")
    net_table.add_column(style="white")
    
    net_options = [
        ("1", "Local IP Configuration"),
        ("2", "Public IP Detection"),
        ("3", "Interface Statistics"),
        ("4", "Return to main menu")
    ]
    
    for key, desc in net_options:
        net_table.add_row(f"[{key}]", desc)
        
    console.print(net_table)
    
    net_choice = Prompt.ask("Enter your choice", choices=["1", "2", "3", "4"], default="1")
    
    if net_choice == "4":
        return
    
    # Initialize network info
    netinfo = NetworkInfo(console)
    
    # Perform requested function
    if net_choice == "1":
        netinfo.show_local_ip()
    elif net_choice == "2":
        netinfo.show_public_ip()
    elif net_choice == "3":
        netinfo.show_interface_stats()
    
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
            
        scanner.scan(args.target, ports)
        
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