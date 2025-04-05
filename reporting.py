import os
import json
import csv
import datetime
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt, Confirm
from database import ScanDatabase

console = Console()

class ReportGenerator:
    """Generate reports from scan results in various formats."""
    
    def __init__(self):
        """Initialize the report generator."""
        self.db = ScanDatabase()
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
    
    def generate_report(self, scan_id, format="html", output_file=None):
        """
        Generate a report from scan results in the specified format.
        
        Args:
            scan_id: The ID of the scan to generate a report for
            format: The format of the report (html, csv, json)
            output_file: The path to save the report to (optional)
            
        Returns:
            The path to the generated report
        """
        # Get scan details
        scan = self.db.get_scan_by_id(scan_id)
        if not scan:
            console.print(f"[red]Scan with ID {scan_id} not found.[/red]")
            return None
        
        # Generate timestamp for filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Generate default filename if not provided
        if not output_file:
            filename = f"{scan['scan_type']}_{scan['target']}_{timestamp}.{format}"
            output_file = os.path.join(self.reports_dir, filename)
        
        # Generate report based on format
        if format.lower() == "html":
            success = self._generate_html_report(scan, output_file)
        elif format.lower() == "csv":
            success = self._generate_csv_report(scan, output_file)
        elif format.lower() == "json":
            success = self._generate_json_report(scan, output_file)
        else:
            console.print(f"[red]Unsupported format: {format}[/red]")
            return None
        
        if success:
            console.print(f"[green]Report generated successfully: {output_file}[/green]")
            return output_file
        else:
            console.print(f"[red]Failed to generate report.[/red]")
            return None
    
    def _generate_html_report(self, scan, output_file):
        """Generate an HTML report for the scan."""
        try:
            scan_type = scan['scan_type']
            
            # Get scan results based on scan type
            if scan_type == 'port_scan':
                results = self.db.get_port_scan_results(scan['id'])
                html_content = self._generate_port_scan_html(scan, results)
            elif scan_type == 'device_discovery':
                results = self.db.get_device_discovery_results(scan['id'])
                html_content = self._generate_device_discovery_html(scan, results)
            else:
                console.print(f"[yellow]HTML report generation not implemented for {scan_type}.[/yellow]")
                return False
            
            # Write HTML to file
            with open(output_file, 'w') as f:
                f.write(html_content)
            
            return True
        except Exception as e:
            console.print(f"[red]Error generating HTML report: {str(e)}[/red]")
            return False
    
    def _generate_csv_report(self, scan, output_file):
        """Generate a CSV report for the scan."""
        try:
            scan_type = scan['scan_type']
            
            # Get scan results based on scan type
            if scan_type == 'port_scan':
                results = self.db.get_port_scan_results(scan['id'])
                
                # Write CSV file
                with open(output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    # Write header
                    writer.writerow(['Port', 'Protocol', 'State', 'Service', 'Banner'])
                    # Write data
                    for result in results:
                        writer.writerow([
                            result['port'],
                            result['protocol'],
                            result['state'],
                            result['service'] or '',
                            result['banner'] or ''
                        ])
            
            elif scan_type == 'device_discovery':
                results = self.db.get_device_discovery_results(scan['id'])
                
                # Write CSV file
                with open(output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    # Write header
                    writer.writerow(['IP Address', 'MAC Address', 'Hostname', 'Device Type', 'Vendor', 'Response Time'])
                    # Write data
                    for result in results:
                        writer.writerow([
                            result['ip_address'],
                            result['mac_address'] or '',
                            result['hostname'] or '',
                            result['device_type'] or '',
                            result['vendor'] or '',
                            result['response_time'] or ''
                        ])
            
            else:
                console.print(f"[yellow]CSV report generation not implemented for {scan_type}.[/yellow]")
                return False
            
            return True
        except Exception as e:
            console.print(f"[red]Error generating CSV report: {str(e)}[/red]")
            return False
    
    def _generate_json_report(self, scan, output_file):
        """Generate a JSON report for the scan."""
        try:
            scan_type = scan['scan_type']
            
            # Create report data structure
            report_data = {
                'scan_id': scan['id'],
                'scan_type': scan['scan_type'],
                'target': scan['target'],
                'timestamp': scan['timestamp'],
                'description': scan['description'],
                'metadata': json.loads(scan['metadata']) if scan['metadata'] else {}
            }
            
            # Get scan results based on scan type
            if scan_type == 'port_scan':
                results = self.db.get_port_scan_results(scan['id'])
                report_data['results'] = [dict(r) for r in results]
            
            elif scan_type == 'device_discovery':
                results = self.db.get_device_discovery_results(scan['id'])
                report_data['results'] = [dict(r) for r in results]
            
            else:
                console.print(f"[yellow]JSON report generation not implemented for {scan_type}.[/yellow]")
                return False
            
            # Write JSON to file
            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            return True
        except Exception as e:
            console.print(f"[red]Error generating JSON report: {str(e)}[/red]")
            return False
    
    def _generate_port_scan_html(self, scan, results):
        """Generate HTML content for a port scan report."""
        # Get scan metadata
        metadata = json.loads(scan['metadata']) if scan['metadata'] else {}
        
        # Count open, filtered, and closed ports
        open_ports = [r for r in results if r['state'] == 'open']
        filtered_ports = [r for r in results if r['state'] == 'filtered']
        closed_ports = [r for r in results if r['state'] == 'closed']
        
        # Generate HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Port Scan Report - {scan['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        .header {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .open {{ color: green; font-weight: bold; }}
        .filtered {{ color: orange; }}
        .closed {{ color: red; }}
        .footer {{ margin-top: 30px; font-size: 0.8em; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Port Scan Report</h1>
        <p><strong>Target:</strong> {scan['target']} ({metadata.get('ip_address', 'Unknown IP')})</p>
        <p><strong>Scan Date:</strong> {scan['timestamp']}</p>
        <p><strong>Scan Type:</strong> {metadata.get('scan_type', 'TCP Connect')}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Ports Scanned:</strong> {len(results)}</p>
        <p><strong>Open Ports:</strong> {len(open_ports)}</p>
        <p><strong>Filtered Ports:</strong> {len(filtered_ports)}</p>
        <p><strong>Closed Ports:</strong> {len(closed_ports)}</p>
    </div>
    
    <h2>Open Ports</h2>
"""
        
        if open_ports:
            html += """
    <table>
        <tr>
            <th>Port</th>
            <th>Protocol</th>
            <th>State</th>
            <th>Service</th>
            <th>Banner</th>
        </tr>
"""
            
            for port in open_ports:
                html += f"""
        <tr>
            <td>{port['port']}</td>
            <td>{port['protocol']}</td>
            <td class="open">{port['state']}</td>
            <td>{port['service'] or ''}</td>
            <td>{port['banner'] or ''}</td>
        </tr>
"""
            
            html += """
    </table>
"""
        else:
            html += """
    <p>No open ports found.</p>
"""
        
        html += """
    <h2>All Scanned Ports</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>Protocol</th>
            <th>State</th>
            <th>Service</th>
        </tr>
"""
        
        for port in results:
            state_class = "open" if port['state'] == 'open' else "filtered" if port['state'] == 'filtered' else "closed"
            html += f"""
        <tr>
            <td>{port['port']}</td>
            <td>{port['protocol']}</td>
            <td class="{state_class}">{port['state']}</td>
            <td>{port['service'] or ''}</td>
        </tr>
"""
        
        html += """
    </table>
    
    <div class="footer">
        <p>Generated by NetworkScanner Pro</p>
    </div>
</body>
</html>
"""
        
        return html
    
    def _generate_device_discovery_html(self, scan, results):
        """Generate HTML content for a device discovery report."""
        # Get scan metadata
        metadata = json.loads(scan['metadata']) if scan['metadata'] else {}
        
        # Generate HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Device Discovery Report - {scan['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        .header {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .footer {{ margin-top: 30px; font-size: 0.8em; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Device Discovery Report</h1>
        <p><strong>Network Range:</strong> {scan['target']}</p>
        <p><strong>Scan Date:</strong> {scan['timestamp']}</p>
        <p><strong>Scan Method:</strong> {metadata.get('scan_method', 'ARP/Ping')}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Devices Found:</strong> {len(results)}</p>
    </div>
    
    <h2>Discovered Devices</h2>
"""
        
        if results:
            html += """
    <table>
        <tr>
            <th>IP Address</th>
            <th>MAC Address</th>
            <th>Hostname</th>
            <th>Vendor</th>
            <th>Response Time</th>
        </tr>
"""
            
            for device in results:
                html += f"""
        <tr>
            <td>{device['ip_address']}</td>
            <td>{device['mac_address'] or ''}</td>
            <td>{device['hostname'] or ''}</td>
            <td>{device['vendor'] or ''}</td>
            <td>{device['response_time'] or ''}</td>
        </tr>
"""
            
            html += """
    </table>
"""
        else:
            html += """
    <p>No devices found.</p>
"""
        
        html += """
    <div class="footer">
        <p>Generated by NetworkScanner Pro</p>
    </div>
</body>
</html>
"""
        
        return html

def show_export_menu(scan_id):
    """Display the export menu and handle user input."""
    db = ScanDatabase()
    scan = db.get_scan_by_id(scan_id)
    
    if not scan:
        console.print(f"[red]Scan with ID {scan_id} not found.[/red]")
        Prompt.ask("Press Enter to continue")
        return
    
    while True:
        console.clear()
        console.print(f"[bold cyan]━━━ EXPORT SCAN RESULTS (ID: {scan_id}) ━━━[/bold cyan]")
        
        # Display scan info
        console.print(f"[bold]Scan Type:[/bold] {scan['scan_type'].replace('_', ' ').title()}")
        console.print(f"[bold]Target:[/bold] {scan['target']}")
        console.print(f"[bold]Date/Time:[/bold] {scan['timestamp']}")
        console.print(f"[bold]Description:[/bold] {scan['description'] or ''}")
        console.print("")
        
        # Create export menu
        console.print("[bold]Select Export Format:[/bold]")
        console.print("  [1] HTML - Rich formatted report with tables and styling")
        console.print("  [2] CSV - Comma-separated values for spreadsheet import")
        console.print("  [3] JSON - Machine-readable format for data processing")
        console.print("  [0] Back - Return to previous menu")
        
        choice = Prompt.ask("\nEnter your choice", choices=["0", "1", "2", "3"], default="0")
        
        if choice == "0":
            break
        
        # Get export format
        format_map = {"1": "html", "2": "csv", "3": "json"}
        export_format = format_map[choice]
        
        # Ask for custom filename
        use_custom_filename = Confirm.ask("Use custom filename?", default=False)
        output_file = None
        
        if use_custom_filename:
            default_filename = f"{scan['scan_type']}_{scan['target']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{export_format}"
            filename = Prompt.ask("Enter filename", default=default_filename)
            output_file = os.path.join("reports", filename)
        
        # Generate report
        report_generator = ReportGenerator()
        report_file = report_generator.generate_report(scan_id, export_format, output_file)
        
        if report_file:
            console.print(f"[green]Report saved to: {report_file}[/green]")
        
        Prompt.ask("Press Enter to continue")
