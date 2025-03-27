import dns.resolver
import dns.reversename
import socket
import time
from typing import List, Dict, Any, Optional, Union
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

class DNSTools:
    """DNS tools module for NetworkScan Pro."""
    
    def __init__(self, console: Console):
        """Initialize DNS tools with the console for output."""
        self.console = console
        
    def lookup_a(self, domain: str, dns_server: Optional[str] = None):
        """
        Perform A record lookup for a domain.
        
        Args:
            domain: Domain name to lookup
            dns_server: Optional DNS server to use
        """
        self.console.print(f"[bold]Looking up A records for [yellow]{domain}[/yellow][/bold]")
        
        try:
            # Create resolver
            resolver = dns.resolver.Resolver()
            
            # Set custom DNS server if provided
            if dns_server:
                resolver.nameservers = [dns_server]
                
            # Create progress spinner
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Looking up A records..."),
                console=self.console
            ) as progress:
                # Create task for progress tracking
                task_id = progress.add_task("Looking up...")
                
                # Perform lookup
                start_time = time.time()
                answers = resolver.resolve(domain, 'A')
                lookup_time = time.time() - start_time
                
            # Display results
            self._display_lookup_results(domain, 'A', answers, lookup_time)
            
        except dns.resolver.NXDOMAIN:
            self.console.print(f"[bold red]Error: Domain {domain} does not exist[/bold red]")
        except dns.resolver.NoAnswer:
            self.console.print(f"[bold yellow]No A records found for {domain}[/bold yellow]")
        except dns.exception.DNSException as e:
            self.console.print(f"[bold red]DNS Error: {str(e)}[/bold red]")
        except Exception as e:
            self.console.print(f"[bold red]Error: {str(e)}[/bold red]")
            
    def lookup_mx(self, domain: str, dns_server: Optional[str] = None):
        """
        Perform MX record lookup for a domain.
        
        Args:
            domain: Domain name to lookup
            dns_server: Optional DNS server to use
        """
        self.console.print(f"[bold]Looking up MX records for [yellow]{domain}[/yellow][/bold]")
        
        try:
            # Create resolver
            resolver = dns.resolver.Resolver()
            
            # Set custom DNS server if provided
            if dns_server:
                resolver.nameservers = [dns_server]
                
            # Create progress spinner
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Looking up MX records..."),
                console=self.console
            ) as progress:
                # Create task for progress tracking
                task_id = progress.add_task("Looking up...")
                
                # Perform lookup
                start_time = time.time()
                answers = resolver.resolve(domain, 'MX')
                lookup_time = time.time() - start_time
                
            # Display results
            self._display_lookup_results(domain, 'MX', answers, lookup_time)
            
        except dns.resolver.NXDOMAIN:
            self.console.print(f"[bold red]Error: Domain {domain} does not exist[/bold red]")
        except dns.resolver.NoAnswer:
            self.console.print(f"[bold yellow]No MX records found for {domain}[/bold yellow]")
        except dns.exception.DNSException as e:
            self.console.print(f"[bold red]DNS Error: {str(e)}[/bold red]")
        except Exception as e:
            self.console.print(f"[bold red]Error: {str(e)}[/bold red]")
            
    def lookup_txt(self, domain: str, dns_server: Optional[str] = None):
        """
        Perform TXT record lookup for a domain.
        
        Args:
            domain: Domain name to lookup
            dns_server: Optional DNS server to use
        """
        self.console.print(f"[bold]Looking up TXT records for [yellow]{domain}[/yellow][/bold]")
        
        try:
            # Create resolver
            resolver = dns.resolver.Resolver()
            
            # Set custom DNS server if provided
            if dns_server:
                resolver.nameservers = [dns_server]
                
            # Create progress spinner
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Looking up TXT records..."),
                console=self.console
            ) as progress:
                # Create task for progress tracking
                task_id = progress.add_task("Looking up...")
                
                # Perform lookup
                start_time = time.time()
                answers = resolver.resolve(domain, 'TXT')
                lookup_time = time.time() - start_time
                
            # Display results
            self._display_lookup_results(domain, 'TXT', answers, lookup_time)
            
        except dns.resolver.NXDOMAIN:
            self.console.print(f"[bold red]Error: Domain {domain} does not exist[/bold red]")
        except dns.resolver.NoAnswer:
            self.console.print(f"[bold yellow]No TXT records found for {domain}[/bold yellow]")
        except dns.exception.DNSException as e:
            self.console.print(f"[bold red]DNS Error: {str(e)}[/bold red]")
        except Exception as e:
            self.console.print(f"[bold red]Error: {str(e)}[/bold red]")
            
    def lookup_ns(self, domain: str, dns_server: Optional[str] = None):
        """
        Perform NS record lookup for a domain.
        
        Args:
            domain: Domain name to lookup
            dns_server: Optional DNS server to use
        """
        self.console.print(f"[bold]Looking up NS records for [yellow]{domain}[/yellow][/bold]")
        
        try:
            # Create resolver
            resolver = dns.resolver.Resolver()
            
            # Set custom DNS server if provided
            if dns_server:
                resolver.nameservers = [dns_server]
                
            # Create progress spinner
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Looking up NS records..."),
                console=self.console
            ) as progress:
                # Create task for progress tracking
                task_id = progress.add_task("Looking up...")
                
                # Perform lookup
                start_time = time.time()
                answers = resolver.resolve(domain, 'NS')
                lookup_time = time.time() - start_time
                
            # Display results
            self._display_lookup_results(domain, 'NS', answers, lookup_time)
            
        except dns.resolver.NXDOMAIN:
            self.console.print(f"[bold red]Error: Domain {domain} does not exist[/bold red]")
        except dns.resolver.NoAnswer:
            self.console.print(f"[bold yellow]No NS records found for {domain}[/bold yellow]")
        except dns.exception.DNSException as e:
            self.console.print(f"[bold red]DNS Error: {str(e)}[/bold red]")
        except Exception as e:
            self.console.print(f"[bold red]Error: {str(e)}[/bold red]")
            
    def reverse_lookup(self, ip: str, dns_server: Optional[str] = None):
        """
        Perform reverse DNS lookup for an IP address.
        
        Args:
            ip: IP address to lookup
            dns_server: Optional DNS server to use
        """
        self.console.print(f"[bold]Performing reverse DNS lookup for [yellow]{ip}[/yellow][/bold]")
        
        try:
            # Create resolver
            resolver = dns.resolver.Resolver()
            
            # Set custom DNS server if provided
            if dns_server:
                resolver.nameservers = [dns_server]
                
            # Create progress spinner
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Performing reverse lookup..."),
                console=self.console
            ) as progress:
                # Create task for progress tracking
                task_id = progress.add_task("Looking up...")
                
                # Perform lookup
                start_time = time.time()
                addr = dns.reversename.from_address(ip)
                answers = resolver.resolve(addr, 'PTR')
                lookup_time = time.time() - start_time
                
            # Create results table
            table = Table(title=f"Reverse DNS Lookup Results for {ip}")
            table.add_column("Hostname", style="green")
            table.add_column("Time (s)", style="cyan", justify="right")
            
            for rdata in answers:
                table.add_row(str(rdata), f"{lookup_time:.4f}")
                
            self.console.print(table)
            
        except dns.resolver.NXDOMAIN:
            self.console.print(f"[bold yellow]No reverse DNS records found for {ip}[/bold yellow]")
        except dns.exception.DNSException as e:
            self.console.print(f"[bold red]DNS Error: {str(e)}[/bold red]")
        except Exception as e:
            self.console.print(f"[bold red]Error: {str(e)}[/bold red]")
            
    def test_dns_server(self, domain: str, dns_server: str):
        """
        Test a DNS server by performing multiple lookups.
        
        Args:
            domain: Domain name to lookup
            dns_server: DNS server to test
        """
        self.console.print(f"[bold]Testing DNS server [yellow]{dns_server}[/yellow] with domain [yellow]{domain}[/yellow][/bold]")
        
        # List of record types to test
        record_types = ['A', 'MX', 'NS', 'TXT']
        results = []
        
        try:
            # Create resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            
            # Create progress spinner
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Testing DNS server..."),
                console=self.console
            ) as progress:
                # Create task for progress tracking
                task_id = progress.add_task("Testing...", total=len(record_types))
                
                # Perform lookups for each record type
                for record_type in record_types:
                    try:
                        start_time = time.time()
                        answers = resolver.resolve(domain, record_type)
                        lookup_time = time.time() - start_time
                        
                        results.append({
                            "record_type": record_type,
                            "status": "success",
                            "count": len(answers),
                            "time": lookup_time
                        })
                        
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        results.append({
                            "record_type": record_type,
                            "status": "no_records",
                            "count": 0,
                            "time": 0
                        })
                        
                    except dns.exception.DNSException as e:
                        results.append({
                            "record_type": record_type,
                            "status": "error",
                            "error": str(e),
                            "count": 0,
                            "time": 0
                        })
                        
                    # Update progress
                    progress.update(task_id, advance=1)
                    
            # Display results
            self._display_dns_test_results(dns_server, domain, results)
            
        except Exception as e:
            self.console.print(f"[bold red]Error testing DNS server: {str(e)}[/bold red]")
    
    def _display_lookup_results(self, domain: str, record_type: str, answers, lookup_time: float):
        """
        Display DNS lookup results in a formatted table.
        
        Args:
            domain: Domain that was looked up
            record_type: Type of record (A, MX, etc.)
            answers: DNS answers
            lookup_time: Time taken for lookup
        """
        # Create results table
        table = Table(title=f"{record_type} Record Lookup Results for {domain}")
        
        if record_type == 'A':
            table.add_column("IP Address", style="yellow")
            table.add_column("TTL", style="green", justify="right")
            table.add_column("Time (s)", style="cyan", justify="right")
            
            for rdata in answers:
                table.add_row(str(rdata), str(answers.ttl), f"{lookup_time:.4f}")
                
        elif record_type == 'MX':
            table.add_column("Priority", style="magenta", justify="right")
            table.add_column("Mail Server", style="yellow")
            table.add_column("TTL", style="green", justify="right")
            table.add_column("Time (s)", style="cyan", justify="right")
            
            for rdata in answers:
                table.add_row(str(rdata.preference), str(rdata.exchange), str(answers.ttl), f"{lookup_time:.4f}")
                
        elif record_type == 'TXT':
            table.add_column("TXT Record", style="yellow")
            table.add_column("TTL", style="green", justify="right")
            table.add_column("Time (s)", style="cyan", justify="right")
            
            for rdata in answers:
                # Join TXT record parts
                txt_data = "".join(str(t) for t in rdata.strings)
                table.add_row(txt_data, str(answers.ttl), f"{lookup_time:.4f}")
                
        elif record_type == 'NS':
            table.add_column("Name Server", style="yellow")
            table.add_column("TTL", style="green", justify="right")
            table.add_column("Time (s)", style="cyan", justify="right")
            
            for rdata in answers:
                table.add_row(str(rdata), str(answers.ttl), f"{lookup_time:.4f}")
                
        self.console.print(table)
        
    def _display_dns_test_results(self, dns_server: str, domain: str, results: List[Dict[str, Any]]):
        """
        Display DNS server test results in a formatted table.
        
        Args:
            dns_server: DNS server that was tested
            domain: Domain that was looked up
            results: List of result dictionaries
        """
        # Create results table
        table = Table(title=f"DNS Server Test Results for {dns_server}")
        table.add_column("Record Type", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Record Count", style="yellow", justify="right")
        table.add_column("Response Time (s)", style="magenta", justify="right")
        
        for result in results:
            record_type = result["record_type"]
            
            if result["status"] == "success":
                status = f"[green]Success[/green]"
                count = str(result["count"])
                time_str = f"{result['time']:.4f}"
            elif result["status"] == "no_records":
                status = f"[yellow]No Records[/yellow]"
                count = "0"
                time_str = "N/A"
            else:
                status = f"[red]Error: {result.get('error', 'Unknown')}"
                count = "0"
                time_str = "N/A"
                
            table.add_row(record_type, status, count, time_str)
            
        self.console.print(table) 