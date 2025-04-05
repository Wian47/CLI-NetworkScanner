import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.prompt import Prompt, Confirm
from rich import print as rprint
import json

from database import ScanDatabase
import reporting

console = Console()

def format_timestamp(timestamp_str):
    """Format an ISO timestamp string to a more readable format."""
    try:
        dt = datetime.datetime.fromisoformat(timestamp_str)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return timestamp_str

def show_history_menu():
    """Display the scan history menu and handle user input."""
    db = ScanDatabase()

    while True:
        console.clear()
        console.print("[bold cyan]━━━ SCAN HISTORY ━━━[/bold cyan]")

        # Create a table for the history menu
        history_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
        history_table.add_column(style="cyan", justify="center", width=3)
        history_table.add_column(style="white", width=25, no_wrap=False)
        history_table.add_column(style="dim", width=40, no_wrap=False)

        history_table.add_row("[1]", "View All Scans", "List all scan history")
        history_table.add_row("[2]", "View Port Scans", "List port scan history")
        history_table.add_row("[3]", "View Device Discovery", "List device discovery history")
        history_table.add_row("[4]", "View Vulnerability Scans", "List vulnerability scan history")
        history_table.add_row("[5]", "View DNS Lookups", "List DNS lookup history")
        history_table.add_row("[6]", "View Traceroutes", "List traceroute history")
        history_table.add_row("[7]", "View SSL Checks", "List SSL certificate check history")
        history_table.add_row("[8]", "View Geolocation Lookups", "List geolocation lookup history")
        history_table.add_row("[9]", "Compare Scans", "Compare two scan results")
        history_table.add_row("[10]", "Delete Scan", "Remove a scan from history")
        history_table.add_row("[0]", "Back to Main Menu", "Return to the main menu")

        console.print(history_table)

        choice = Prompt.ask("\nEnter your choice", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"], default="0")

        if choice == "0":
            break
        elif choice == "1":
            view_scan_list()
        elif choice == "2":
            view_scan_list("port_scan")
        elif choice == "3":
            view_scan_list("device_discovery")
        elif choice == "4":
            view_scan_list("vulnerability_scan")
        elif choice == "5":
            view_scan_list("dns_lookup")
        elif choice == "6":
            view_scan_list("traceroute")
        elif choice == "7":
            view_scan_list("ssl_check")
        elif choice == "8":
            view_scan_list("geolocation")
        elif choice == "9":
            compare_scans()
        elif choice == "10":
            delete_scan()

    db.close()

def view_scan_list(scan_type=None):
    """Display a list of scans, optionally filtered by type."""
    db = ScanDatabase()

    # Get scans from the database
    scans = db.get_all_scans(scan_type)

    if not scans:
        console.print(f"\n[yellow]No {scan_type if scan_type else 'scan'} history found.[/yellow]")
        Prompt.ask("Press Enter to continue")
        return

    while True:
        console.clear()
        title = f"[bold cyan]━━━ {'ALL SCANS' if not scan_type else scan_type.upper().replace('_', ' ') + ' HISTORY'} ━━━[/bold cyan]"
        console.print(title)

        # Create a table for the scan list
        scan_table = Table(box=box.SIMPLE_HEAD)
        scan_table.add_column("ID", style="cyan", justify="center")
        scan_table.add_column("Type", style="green")
        scan_table.add_column("Target", style="yellow")
        scan_table.add_column("Date/Time", style="magenta")
        scan_table.add_column("Description", style="white")

        for scan in scans:
            scan_table.add_row(
                str(scan['id']),
                scan['scan_type'].replace('_', ' ').title(),
                scan['target'],
                format_timestamp(scan['timestamp']),
                scan['description'] or ""
            )

        console.print(scan_table)

        console.print("\n[dim]Enter a scan ID to view details, or 0 to go back[/dim]")
        choice = Prompt.ask("Enter your choice", default="0")

        if choice == "0":
            break

        try:
            scan_id = int(choice)
            scan = db.get_scan_by_id(scan_id)

            if scan:
                view_scan_details(scan_id, scan['scan_type'])
            else:
                console.print(f"[red]Scan with ID {scan_id} not found.[/red]")
                Prompt.ask("Press Enter to continue")
        except ValueError:
            console.print("[red]Invalid input. Please enter a valid scan ID.[/red]")
            Prompt.ask("Press Enter to continue")

    db.close()

def view_scan_details(scan_id, scan_type):
    """Display detailed results for a specific scan."""
    db = ScanDatabase()
    scan = db.get_scan_by_id(scan_id)

    if not scan:
        console.print(f"[red]Scan with ID {scan_id} not found.[/red]")
        Prompt.ask("Press Enter to continue")
        return

    console.clear()
    console.print(f"[bold cyan]━━━ SCAN DETAILS (ID: {scan_id}) ━━━[/bold cyan]")

    # Display scan metadata
    metadata_table = Table(box=box.SIMPLE)
    metadata_table.add_column("Property", style="cyan")
    metadata_table.add_column("Value", style="white")

    metadata_table.add_row("Scan Type", scan['scan_type'].replace('_', ' ').title())
    metadata_table.add_row("Target", scan['target'])
    metadata_table.add_row("Date/Time", format_timestamp(scan['timestamp']))
    if scan['description']:
        metadata_table.add_row("Description", scan['description'])
    if scan['metadata']:
        try:
            metadata = json.loads(scan['metadata'])
            for key, value in metadata.items():
                metadata_table.add_row(key.replace('_', ' ').title(), str(value))
        except:
            metadata_table.add_row("Metadata", scan['metadata'])

    console.print(metadata_table)
    console.print("")

    # Display scan-specific results
    if scan_type == 'port_scan':
        display_port_scan_results(db, scan_id)
    elif scan_type == 'device_discovery':
        display_device_discovery_results(db, scan_id)
    elif scan_type == 'vulnerability_scan':
        display_vulnerability_scan_results(db, scan_id)
    elif scan_type == 'dns_lookup':
        display_dns_lookup_results(db, scan_id)
    elif scan_type == 'traceroute':
        display_traceroute_results(db, scan_id)
    elif scan_type == 'ssl_check':
        display_ssl_certificate_results(db, scan_id)
    elif scan_type == 'geolocation':
        display_geolocation_results(db, scan_id)
    else:
        console.print(f"[yellow]No specific viewer available for {scan_type} results.[/yellow]")

    # Add export option
    console.print("\n[bold]Options:[/bold]")
    console.print("  [E] Export - Export scan results to file")
    console.print("  [B] Back - Return to scan list")

    choice = Prompt.ask("Enter your choice", choices=["E", "B"], default="B")

    if choice == "E":
        reporting.show_export_menu(scan_id)

    db.close()

def display_port_scan_results(db, scan_id):
    """Display port scan results in a table."""
    results = db.get_port_scan_results(scan_id)

    if not results:
        console.print("[yellow]No port scan results found.[/yellow]")
        return

    console.print("[bold]Port Scan Results:[/bold]")

    result_table = Table(box=box.SIMPLE_HEAD)
    result_table.add_column("Port", style="cyan", justify="right")
    result_table.add_column("Protocol", style="green")
    result_table.add_column("State", style="yellow")
    result_table.add_column("Service", style="magenta")
    result_table.add_column("Banner", style="white")

    for result in results:
        state_style = "green" if result['state'] == 'open' else "red"
        result_table.add_row(
            str(result['port']),
            result['protocol'],
            f"[{state_style}]{result['state']}[/{state_style}]",
            result['service'] or "",
            (result['banner'] or "")[:50]  # Truncate long banners
        )

    console.print(result_table)

def display_device_discovery_results(db, scan_id):
    """Display device discovery results in a table."""
    results = db.get_device_discovery_results(scan_id)

    if not results:
        console.print("[yellow]No device discovery results found.[/yellow]")
        return

    console.print("[bold]Device Discovery Results:[/bold]")

    result_table = Table(box=box.SIMPLE_HEAD)
    result_table.add_column("IP Address", style="cyan")
    result_table.add_column("MAC Address", style="green")
    result_table.add_column("Hostname", style="yellow")
    result_table.add_column("Device Type", style="magenta")
    result_table.add_column("Vendor", style="white")
    result_table.add_column("Response Time", style="dim")

    for result in results:
        result_table.add_row(
            result['ip_address'],
            result['mac_address'] or "",
            result['hostname'] or "",
            result['device_type'] or "",
            result['vendor'] or "",
            f"{result['response_time']}ms" if result['response_time'] else ""
        )

    console.print(result_table)

def display_vulnerability_scan_results(db, scan_id):
    """Display vulnerability scan results in a table."""
    results = db.get_vulnerability_scan_results(scan_id)

    if not results:
        console.print("[yellow]No vulnerability scan results found.[/yellow]")
        return

    console.print("[bold]Vulnerability Scan Results:[/bold]")

    result_table = Table(box=box.SIMPLE_HEAD)
    result_table.add_column("Target", style="cyan")
    result_table.add_column("Vulnerability", style="yellow")
    result_table.add_column("Severity", style="red")
    result_table.add_column("Description", style="white")
    result_table.add_column("Recommendation", style="green")

    for result in results:
        severity_style = "red" if result['severity'] == 'high' else "yellow" if result['severity'] == 'medium' else "green"
        result_table.add_row(
            result['target'],
            result['vulnerability'],
            f"[{severity_style}]{result['severity']}[/{severity_style}]" if result['severity'] else "",
            result['description'] or "",
            result['recommendation'] or ""
        )

    console.print(result_table)

def display_dns_lookup_results(db, scan_id):
    """Display DNS lookup results in a table."""
    results = db.get_dns_lookup_results(scan_id)

    if not results:
        console.print("[yellow]No DNS lookup results found.[/yellow]")
        return

    console.print("[bold]DNS Lookup Results:[/bold]")

    result_table = Table(box=box.SIMPLE_HEAD)
    result_table.add_column("Query", style="cyan")
    result_table.add_column("Record Type", style="green")
    result_table.add_column("Result", style="white")

    for result in results:
        result_table.add_row(
            result['query'],
            result['record_type'],
            result['result'] or "No result"
        )

    console.print(result_table)

def display_traceroute_results(db, scan_id):
    """Display traceroute results in a table."""
    results = db.get_traceroute_results(scan_id)

    if not results:
        console.print("[yellow]No traceroute results found.[/yellow]")
        return

    console.print("[bold]Traceroute Results:[/bold]")

    result_table = Table(box=box.SIMPLE_HEAD)
    result_table.add_column("Hop", style="cyan", justify="right")
    result_table.add_column("IP Address", style="green")
    result_table.add_column("Hostname", style="yellow")
    result_table.add_column("Response Time", style="white")

    for result in results:
        result_table.add_row(
            str(result['hop_number']),
            result['ip_address'] or "*",
            result['hostname'] or "",
            f"{result['response_time']}ms" if result['response_time'] else "*"
        )

    console.print(result_table)

def display_ssl_certificate_results(db, scan_id):
    """Display SSL certificate results in a table."""
    results = db.get_ssl_certificate_results(scan_id)

    if not results:
        console.print("[yellow]No SSL certificate results found.[/yellow]")
        return

    console.print("[bold]SSL Certificate Results:[/bold]")

    for result in results:
        panel = Panel(
            f"[cyan]Hostname:[/cyan] {result['hostname']}\n"
            f"[cyan]Issued To:[/cyan] {result['issued_to'] or 'N/A'}\n"
            f"[cyan]Issued By:[/cyan] {result['issued_by'] or 'N/A'}\n"
            f"[cyan]Valid From:[/cyan] {result['valid_from'] or 'N/A'}\n"
            f"[cyan]Valid Until:[/cyan] {result['valid_until'] or 'N/A'}\n"
            f"[cyan]Valid:[/cyan] {'[green]Yes[/green]' if result['is_valid'] else '[red]No[/red]'}\n",
            title=f"Certificate for {result['hostname']}",
            border_style="green" if result['is_valid'] else "red"
        )
        console.print(panel)

        if result['issues']:
            try:
                issues = json.loads(result['issues'])
                if issues:
                    console.print("[bold red]Issues:[/bold red]")
                    for issue in issues:
                        console.print(f"- {issue}")
            except:
                console.print(f"[bold red]Issues:[/bold red] {result['issues']}")

def display_geolocation_results(db, scan_id):
    """Display geolocation results in a table."""
    results = db.get_geolocation_results(scan_id)

    if not results:
        console.print("[yellow]No geolocation results found.[/yellow]")
        return

    console.print("[bold]Geolocation Results:[/bold]")

    for result in results:
        panel = Panel(
            f"[cyan]IP Address:[/cyan] {result['ip_address']}\n"
            f"[cyan]Country:[/cyan] {result['country'] or 'N/A'}\n"
            f"[cyan]Region:[/cyan] {result['region'] or 'N/A'}\n"
            f"[cyan]City:[/cyan] {result['city'] or 'N/A'}\n"
            f"[cyan]Coordinates:[/cyan] {f'{result['latitude']}, {result['longitude']}' if result['latitude'] and result['longitude'] else 'N/A'}\n"
            f"[cyan]ISP:[/cyan] {result['isp'] or 'N/A'}\n",
            title=f"Geolocation for {result['ip_address']}",
            border_style="blue"
        )
        console.print(panel)

def compare_scans():
    """Compare two scans of the same type."""
    db = ScanDatabase()

    console.clear()
    console.print("[bold cyan]━━━ COMPARE SCANS ━━━[/bold cyan]")

    # First, select the scan type
    scan_type_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue", padding=(0, 1))
    scan_type_table.add_column(style="cyan", justify="center", width=3)
    scan_type_table.add_column(style="white", width=25)

    scan_type_table.add_row("[1]", "Port Scans")
    scan_type_table.add_row("[2]", "Device Discovery")
    scan_type_table.add_row("[0]", "Back")

    console.print(scan_type_table)

    choice = Prompt.ask("\nSelect scan type to compare", choices=["0", "1", "2"], default="0")

    if choice == "0":
        return

    scan_type = "port_scan" if choice == "1" else "device_discovery"

    # Get scans of the selected type
    scans = db.get_all_scans(scan_type)

    if len(scans) < 2:
        console.print(f"[yellow]Need at least 2 {scan_type.replace('_', ' ')} scans to compare.[/yellow]")
        Prompt.ask("Press Enter to continue")
        return

    # Display available scans
    console.clear()
    console.print(f"[bold cyan]━━━ SELECT SCANS TO COMPARE ({scan_type.upper().replace('_', ' ')}) ━━━[/bold cyan]")

    scan_table = Table(box=box.SIMPLE_HEAD)
    scan_table.add_column("ID", style="cyan", justify="center")
    scan_table.add_column("Target", style="yellow")
    scan_table.add_column("Date/Time", style="magenta")
    scan_table.add_column("Description", style="white")

    for scan in scans:
        scan_table.add_row(
            str(scan['id']),
            scan['target'],
            format_timestamp(scan['timestamp']),
            scan['description'] or ""
        )

    console.print(scan_table)

    # Select first scan
    scan_id1 = Prompt.ask("\nEnter ID of first scan", default="0")
    if scan_id1 == "0":
        return

    # Select second scan
    scan_id2 = Prompt.ask("Enter ID of second scan", default="0")
    if scan_id2 == "0":
        return

    try:
        scan_id1 = int(scan_id1)
        scan_id2 = int(scan_id2)

        # Get scan details
        scan1 = db.get_scan_by_id(scan_id1)
        scan2 = db.get_scan_by_id(scan_id2)

        if not scan1 or not scan2:
            console.print("[red]One or both scan IDs not found.[/red]")
            Prompt.ask("Press Enter to continue")
            return

        if scan1['scan_type'] != scan_type or scan2['scan_type'] != scan_type:
            console.print("[red]Both scans must be of the same type.[/red]")
            Prompt.ask("Press Enter to continue")
            return

        # Compare scans
        console.clear()
        console.print(f"[bold cyan]━━━ SCAN COMPARISON RESULTS ━━━[/bold cyan]")

        console.print(f"[bold]Comparing:[/bold]")
        console.print(f"[cyan]Scan 1:[/cyan] ID {scan_id1}, {scan1['target']}, {format_timestamp(scan1['timestamp'])}")
        console.print(f"[cyan]Scan 2:[/cyan] ID {scan_id2}, {scan2['target']}, {format_timestamp(scan2['timestamp'])}")
        console.print("")

        if scan_type == "port_scan":
            compare_port_scan_results(db, scan_id1, scan_id2)
        elif scan_type == "device_discovery":
            compare_device_discovery_results(db, scan_id1, scan_id2)

    except ValueError:
        console.print("[red]Invalid input. Please enter valid scan IDs.[/red]")

    Prompt.ask("\nPress Enter to continue")
    db.close()

def compare_port_scan_results(db, scan_id1, scan_id2):
    """Compare and display differences between two port scans."""
    differences = db.compare_port_scans(scan_id1, scan_id2)

    if not any(differences.values()):
        console.print("[green]No differences found between the scans.[/green]")
        return

    # Display ports only in first scan
    if differences['only_in_scan1']:
        console.print("[bold yellow]Ports found in first scan but not in second:[/bold yellow]")

        table = Table(box=box.SIMPLE_HEAD)
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("Protocol", style="green")
        table.add_column("State", style="yellow")

        for port in differences['only_in_scan1']:
            table.add_row(
                str(port['port']),
                port['protocol'],
                port['state']
            )

        console.print(table)

    # Display ports only in second scan
    if differences['only_in_scan2']:
        console.print("[bold yellow]Ports found in second scan but not in first:[/bold yellow]")

        table = Table(box=box.SIMPLE_HEAD)
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("Protocol", style="green")
        table.add_column("State", style="yellow")

        for port in differences['only_in_scan2']:
            table.add_row(
                str(port['port']),
                port['protocol'],
                port['state']
            )

        console.print(table)

    # Display ports with different states
    if differences['different_state']:
        console.print("[bold yellow]Ports with different states:[/bold yellow]")

        table = Table(box=box.SIMPLE_HEAD)
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("Protocol", style="green")
        table.add_column("First Scan", style="magenta")
        table.add_column("Second Scan", style="blue")

        for port in differences['different_state']:
            table.add_row(
                str(port['port']),
                port['protocol'],
                port['state1'],
                port['state2']
            )

        console.print(table)

def compare_device_discovery_results(db, scan_id1, scan_id2):
    """Compare and display differences between two device discovery scans."""
    differences = db.compare_device_discovery(scan_id1, scan_id2)

    if not any(differences.values()):
        console.print("[green]No differences found between the scans.[/green]")
        return

    # Display devices only in first scan
    if differences['only_in_scan1']:
        console.print("[bold yellow]Devices found in first scan but not in second:[/bold yellow]")

        table = Table(box=box.SIMPLE_HEAD)
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="green")
        table.add_column("Hostname", style="yellow")

        for device in differences['only_in_scan1']:
            table.add_row(
                device['ip_address'],
                device['mac_address'] or "",
                device['hostname'] or ""
            )

        console.print(table)

    # Display devices only in second scan
    if differences['only_in_scan2']:
        console.print("[bold yellow]Devices found in second scan but not in first:[/bold yellow]")

        table = Table(box=box.SIMPLE_HEAD)
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="green")
        table.add_column("Hostname", style="yellow")

        for device in differences['only_in_scan2']:
            table.add_row(
                device['ip_address'],
                device['mac_address'] or "",
                device['hostname'] or ""
            )

        console.print(table)

    # Display devices with different properties
    if differences['different_properties']:
        console.print("[bold yellow]Devices with changed properties:[/bold yellow]")

        for device in differences['different_properties']:
            console.print(f"[cyan]{device['ip_address']}[/cyan]:")

            for prop, values in device['differences'].items():
                console.print(f"  [yellow]{prop}[/yellow]: {values['old']} → {values['new']}")

            console.print("")

def delete_scan():
    """Delete a scan from the database."""
    db = ScanDatabase()

    console.clear()
    console.print("[bold cyan]━━━ DELETE SCAN ━━━[/bold cyan]")

    # Get all scans
    scans = db.get_all_scans()

    if not scans:
        console.print("[yellow]No scan history found.[/yellow]")
        Prompt.ask("Press Enter to continue")
        return

    # Display available scans
    scan_table = Table(box=box.SIMPLE_HEAD)
    scan_table.add_column("ID", style="cyan", justify="center")
    scan_table.add_column("Type", style="green")
    scan_table.add_column("Target", style="yellow")
    scan_table.add_column("Date/Time", style="magenta")
    scan_table.add_column("Description", style="white")

    for scan in scans:
        scan_table.add_row(
            str(scan['id']),
            scan['scan_type'].replace('_', ' ').title(),
            scan['target'],
            format_timestamp(scan['timestamp']),
            scan['description'] or ""
        )

    console.print(scan_table)

    # Select scan to delete
    scan_id = Prompt.ask("\nEnter ID of scan to delete (0 to cancel)", default="0")
    if scan_id == "0":
        return

    try:
        scan_id = int(scan_id)
        scan = db.get_scan_by_id(scan_id)

        if not scan:
            console.print(f"[red]Scan with ID {scan_id} not found.[/red]")
            Prompt.ask("Press Enter to continue")
            return

        # Confirm deletion
        if Confirm.ask(f"Are you sure you want to delete scan {scan_id} ({scan['scan_type']}, {scan['target']}, {format_timestamp(scan['timestamp'])})"):
            if db.delete_scan(scan_id):
                console.print(f"[green]Scan {scan_id} deleted successfully.[/green]")
            else:
                console.print(f"[red]Failed to delete scan {scan_id}.[/red]")

    except ValueError:
        console.print("[red]Invalid input. Please enter a valid scan ID.[/red]")

    Prompt.ask("Press Enter to continue")
    db.close()
