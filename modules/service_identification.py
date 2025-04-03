import re
import socket
import time
import json
import os
import urllib.request
import urllib.error
import ssl
from typing import Dict, Any, List, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

class ServiceIdentifier:
    """Service identification and vulnerability checking module for NetworkScan Pro."""
    
    def __init__(self, console: Console = None):
        """Initialize the service identifier."""
        self.console = console or Console()
        self.service_signatures = self._load_service_signatures()
        self.vulnerability_db = self._load_vulnerability_db()
        
    def _load_service_signatures(self) -> Dict[str, List[Dict[str, str]]]:
        """
        Load service signatures from the signatures database file.
        If the file doesn't exist, create a default one.
        
        Returns:
            Dictionary of service signatures by port
        """
        signatures_file = os.path.join(os.path.dirname(__file__), 'data', 'service_signatures.json')
        
        # Create data directory if it doesn't exist
        os.makedirs(os.path.dirname(signatures_file), exist_ok=True)
        
        # Check if signatures file exists, if not create it with default signatures
        if not os.path.exists(signatures_file):
            default_signatures = {
                "21": [
                    {"regex": r"FTP server \(Version ([\d\.]+)", "service": "Generic FTP", "version_group": 1},
                    {"regex": r"FileZilla Server ([\d\.]+)", "service": "FileZilla FTP", "version_group": 1},
                    {"regex": r"ProFTPD ([\d\.]+)", "service": "ProFTPD", "version_group": 1},
                    {"regex": r"Pure-FTPd", "service": "Pure-FTPd", "version_group": None},
                    {"regex": r"vsFTPd ([\d\.]+)", "service": "vsFTPd", "version_group": 1}
                ],
                "22": [
                    {"regex": r"SSH-([\d\.]+)-OpenSSH[_-]([\d\.]+)", "service": "OpenSSH", "version_group": 2},
                    {"regex": r"SSH-([\d\.]+)-dropbear_([\d\.]+)", "service": "Dropbear SSH", "version_group": 2}
                ],
                "23": [
                    {"regex": r"Welcome to ([\w\s]+) Telnet", "service": "Telnet", "version_group": None}
                ],
                "25": [
                    {"regex": r"220 .* ESMTP Postfix \(([^\)]+)\)", "service": "Postfix SMTP", "version_group": 1},
                    {"regex": r"220 .* ESMTP Sendmail ([^;]+);", "service": "Sendmail SMTP", "version_group": 1},
                    {"regex": r"220 .* ESMTP Exim ([\d\.]+)", "service": "Exim SMTP", "version_group": 1}
                ],
                "80": [
                    {"regex": r"Server: Apache/([\d\.]+)", "service": "Apache", "version_group": 1},
                    {"regex": r"Server: nginx/([\d\.]+)", "service": "Nginx", "version_group": 1},
                    {"regex": r"Server: Microsoft-IIS/([\d\.]+)", "service": "IIS", "version_group": 1},
                    {"regex": r"Server: lighttpd/([\d\.]+)", "service": "Lighttpd", "version_group": 1}
                ],
                "443": [
                    {"regex": r"Server: Apache/([\d\.]+)", "service": "Apache SSL", "version_group": 1},
                    {"regex": r"Server: nginx/([\d\.]+)", "service": "Nginx SSL", "version_group": 1},
                    {"regex": r"Server: Microsoft-IIS/([\d\.]+)", "service": "IIS SSL", "version_group": 1}
                ],
                "3306": [
                    {"regex": r"([.\d]+)-MariaDB", "service": "MariaDB", "version_group": 1},
                    {"regex": r"([.\d]+)-MySQL", "service": "MySQL", "version_group": 1}
                ],
                "5432": [
                    {"regex": r"PostgreSQL ([\d\.]+)", "service": "PostgreSQL", "version_group": 1}
                ],
                "27017": [
                    {"regex": r"MongoDB ([\d\.]+)", "service": "MongoDB", "version_group": 1}
                ]
            }
            
            # Save default signatures
            os.makedirs(os.path.dirname(signatures_file), exist_ok=True)
            with open(signatures_file, 'w') as f:
                json.dump(default_signatures, f, indent=2)
                
            return default_signatures
        
        # Load existing signatures
        try:
            with open(signatures_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.console.print(f"[bold red]Error loading service signatures: {str(e)}[/bold red]")
            return {}
            
    def _load_vulnerability_db(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load vulnerability database from file.
        If the file doesn't exist, create a default one.
        
        Returns:
            Dictionary of vulnerabilities by service
        """
        vuln_file = os.path.join(os.path.dirname(__file__), 'data', 'vulnerabilities.json')
        
        # Create data directory if it doesn't exist
        os.makedirs(os.path.dirname(vuln_file), exist_ok=True)
        
        # Check if vulnerability file exists, if not create it with default data
        if not os.path.exists(vuln_file):
            default_vulns = {
                "OpenSSH": [
                    {
                        "versions": ["7.2p1", "7.2p2"],
                        "cve": "CVE-2016-6210",
                        "description": "User enumeration via timing attack",
                        "severity": "Medium",
                        "fixed_in": "7.3p1"
                    },
                    {
                        "versions": ["<7.4"],
                        "cve": "CVE-2016-10009",
                        "description": "Privilege escalation via agent forwarding",
                        "severity": "High",
                        "fixed_in": "7.4"
                    }
                ],
                "Apache": [
                    {
                        "versions": ["2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.4.4", "2.4.5", "2.4.6", "2.4.7", "2.4.8", "2.4.9"],
                        "cve": "CVE-2014-0226",
                        "description": "Race condition in mod_status",
                        "severity": "High",
                        "fixed_in": "2.4.10"
                    },
                    {
                        "versions": ["2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.4.4", "2.4.5", "2.4.6", "2.4.7", "2.4.8", "2.4.9", "2.4.10", "2.4.11", "2.4.12", "2.4.13", "2.4.14", "2.4.15", "2.4.16"],
                        "cve": "CVE-2016-5387",
                        "description": "HTTP header injection via HTTP_PROXY",
                        "severity": "Medium",
                        "fixed_in": "2.4.17"
                    }
                ],
                "Nginx": [
                    {
                        "versions": ["<1.5.11"],
                        "cve": "CVE-2014-0133",
                        "description": "SPDY heap buffer overflow",
                        "severity": "High",
                        "fixed_in": "1.5.11"
                    }
                ],
                "IIS": [
                    {
                        "versions": ["7.5"],
                        "cve": "CVE-2010-3972",
                        "description": "FTP service stack overflow",
                        "severity": "High",
                        "fixed_in": "Patch MS11-004"
                    }
                ],
                "MySQL": [
                    {
                        "versions": ["<5.7.19"],
                        "cve": "CVE-2017-3636",
                        "description": "Privilege escalation vulnerability",
                        "severity": "High",
                        "fixed_in": "5.7.19"
                    }
                ],
                "MariaDB": [
                    {
                        "versions": ["<10.2.8"],
                        "cve": "CVE-2017-3636",
                        "description": "Privilege escalation vulnerability",
                        "severity": "High",
                        "fixed_in": "10.2.8"
                    }
                ],
                "vsFTPd": [
                    {
                        "versions": ["2.3.4"],
                        "cve": "CVE-2011-2523",
                        "description": "Backdoor vulnerability",
                        "severity": "Critical",
                        "fixed_in": "2.3.5"
                    }
                ]
            }
            
            # Save default vulnerabilities
            with open(vuln_file, 'w') as f:
                json.dump(default_vulns, f, indent=2)
                
            return default_vulns
        
        # Load existing vulnerabilities
        try:
            with open(vuln_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.console.print(f"[bold red]Error loading vulnerability database: {str(e)}[/bold red]")
            return {}
    
    def identify_service(self, ip: str, port: int, banner: Optional[str] = None) -> Dict[str, Any]:
        """
        Identify service and version based on port and banner.
        
        Args:
            ip: Target IP address
            port: Port number
            banner: Optional banner string if already captured
            
        Returns:
            Dictionary with service identification information
        """
        result = {
            "service_name": "Unknown",
            "version": None,
            "product": None,
            "banner": banner,
            "vulnerabilities": []
        }
        
        # If no banner provided, try to grab one
        if not banner:
            banner = self._grab_banner(ip, port)
            result["banner"] = banner
            
        # If we have a banner, try to identify the service
        if banner:
            service_info = self._identify_from_banner(port, banner)
            if service_info:
                result.update(service_info)
                
                # Check for vulnerabilities
                if result["service_name"] and result["version"]:
                    vulns = self._check_vulnerabilities(result["service_name"], result["version"])
                    result["vulnerabilities"] = vulns
        
        # If we couldn't identify from banner, try HTTP detection for web ports
        if result["service_name"] == "Unknown" and port in [80, 443, 8080, 8443]:
            http_info = self._identify_http_service(ip, port)
            if http_info:
                result.update(http_info)
                
                # Check for vulnerabilities
                if result["service_name"] and result["version"]:
                    vulns = self._check_vulnerabilities(result["service_name"], result["version"])
                    result["vulnerabilities"] = vulns
                    
        return result
    
    def _grab_banner(self, ip: str, port: int) -> Optional[str]:
        """
        Attempt to grab a service banner from the specified port.
        
        Args:
            ip: Target IP address
            port: Port number
            
        Returns:
            Banner string or None if no banner could be grabbed
        """
        # Different protocols need different approaches
        if port in [21, 22, 25, 110, 143, 587]:
            # Text-based protocols that send banner on connect
            return self._grab_text_banner(ip, port)
        elif port in [80, 443, 8080, 8443]:
            # HTTP/HTTPS services
            return self._grab_http_banner(ip, port)
        elif port in [3306]:
            # MySQL/MariaDB
            return self._grab_mysql_banner(ip, port)
        elif port in [5432]:
            # PostgreSQL
            return self._grab_postgres_banner(ip, port)
        
        # Default to basic text banner grab for unknown protocols
        return self._grab_text_banner(ip, port)
    
    def _grab_text_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab banner from text-based protocols."""
        try:
            # Create socket with short timeout
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((ip, port))
            
            # Some protocols need a prompt
            if port == 25:  # SMTP
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                # Send EHLO to get more info
                s.send(b'EHLO networkscanner.local\r\n')
                response = s.recv(1024).decode('utf-8', errors='ignore').strip()
                banner += "\n" + response
            else:
                # For most protocols, just receive the banner
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                
            s.close()
            return banner
        except Exception as e:
            return None
    
    def _grab_http_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab banner from HTTP/HTTPS services."""
        try:
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{ip}:{port}"
            
            # Create SSL context that ignores certificate errors for HTTPS
            context = ssl._create_unverified_context() if protocol == "https" else None
            
            # Create request with custom User-Agent
            request = urllib.request.Request(
                url,
                headers={'User-Agent': 'Mozilla/5.0 NetworkScanPro/1.0'}
            )
            
            # Send request and get response
            if context:
                response = urllib.request.urlopen(request, timeout=3, context=context)
            else:
                response = urllib.request.urlopen(request, timeout=3)
                
            # Extract headers as banner
            headers = response.info()
            banner = f"HTTP/{response.version / 10.0} {response.status} {response.reason}\n"
            
            for header in headers:
                banner += f"{header}: {headers[header]}\n"
                
            return banner
        except Exception as e:
            return None
    
    def _grab_mysql_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab banner from MySQL/MariaDB services."""
        try:
            # Create socket with short timeout
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((ip, port))
            
            # MySQL sends a handshake packet on connect
            packet = s.recv(1024)
            s.close()
            
            # Extract version from packet
            if len(packet) > 5:
                # Skip packet header (4 bytes) and protocol version (1 byte)
                version_str = ""
                for i in range(5, len(packet)):
                    if packet[i] == 0:  # Null terminator
                        break
                    version_str += chr(packet[i])
                
                return version_str
            
            return None
        except Exception as e:
            return None
    
    def _grab_postgres_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab banner from PostgreSQL services."""
        try:
            # Create socket with short timeout
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((ip, port))
            
            # Send a startup message packet
            # Format: Length (4 bytes) + Protocol (4 bytes) + "user\0postgres\0database\0postgres\0\0"
            startup_packet = b'\x00\x00\x00\x21\x00\x03\x00\x00user\x00postgres\x00database\x00postgres\x00\x00'
            s.send(startup_packet)
            
            # Receive response
            response = s.recv(1024)
            s.close()
            
            # Check if we got an error response which contains version info
            if response and len(response) > 1 and response[0] == ord('E'):
                return response.decode('utf-8', errors='ignore')
            
            return None
        except Exception as e:
            return None
    
    def _identify_from_banner(self, port: str, banner: str) -> Dict[str, Any]:
        """
        Identify service and version from banner using regex patterns.
        
        Args:
            port: Port number as string
            banner: Banner string
            
        Returns:
            Dictionary with service identification information
        """
        result = {
            "service_name": "Unknown",
            "version": None,
            "product": None
        }
        
        # Get signatures for this port
        port_str = str(port)
        signatures = self.service_signatures.get(port_str, [])
        
        # If no specific signatures for this port, try generic ones
        if not signatures:
            signatures = self.service_signatures.get("generic", [])
        
        # Try each signature
        for signature in signatures:
            match = re.search(signature["regex"], banner, re.IGNORECASE)
            if match:
                result["service_name"] = signature["service"]
                result["product"] = signature["service"]
                
                # Extract version if available
                if signature["version_group"] is not None:
                    try:
                        result["version"] = match.group(signature["version_group"])
                    except:
                        pass
                        
                return result
        
        # If we get here, no signature matched
        return result
    
    def _identify_http_service(self, ip: str, port: int) -> Dict[str, Any]:
        """
        Identify HTTP service and version.
        
        Args:
            ip: Target IP address
            port: Port number
            
        Returns:
            Dictionary with service identification information
        """
        result = {
            "service_name": "Unknown",
            "version": None,
            "product": None,
            "banner": None
        }
        
        try:
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{ip}:{port}"
            
            # Create SSL context that ignores certificate errors for HTTPS
            context = ssl._create_unverified_context() if protocol == "https" else None
            
            # Create request with custom User-Agent
            request = urllib.request.Request(
                url,
                headers={'User-Agent': 'Mozilla/5.0 NetworkScanPro/1.0'}
            )
            
            # Send request and get response
            if context:
                response = urllib.request.urlopen(request, timeout=3, context=context)
            else:
                response = urllib.request.urlopen(request, timeout=3)
                
            # Check for Server header
            server = response.getheader('Server')
            if server:
                result["banner"] = f"Server: {server}"
                
                # Try to identify server from header
                if "Apache" in server:
                    result["service_name"] = "Apache"
                    result["product"] = "Apache"
                    # Try to extract version
                    match = re.search(r"Apache/([\d\.]+)", server)
                    if match:
                        result["version"] = match.group(1)
                elif "nginx" in server:
                    result["service_name"] = "Nginx"
                    result["product"] = "Nginx"
                    # Try to extract version
                    match = re.search(r"nginx/([\d\.]+)", server)
                    if match:
                        result["version"] = match.group(1)
                elif "Microsoft-IIS" in server:
                    result["service_name"] = "IIS"
                    result["product"] = "IIS"
                    # Try to extract version
                    match = re.search(r"Microsoft-IIS/([\d\.]+)", server)
                    if match:
                        result["version"] = match.group(1)
                else:
                    # Generic web server
                    result["service_name"] = "HTTP Server"
                    result["product"] = server
            else:
                # No Server header, but still a web server
                result["service_name"] = "HTTP Server"
                result["product"] = "Unknown Web Server"
                
            return result
        except Exception as e:
            # Failed to connect or process
            return result
    
    def _check_vulnerabilities(self, service_name: str, version: str) -> List[Dict[str, Any]]:
        """
        Check for known vulnerabilities for the identified service and version.
        
        Args:
            service_name: Name of the service
            version: Version string
            
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        # Get vulnerabilities for this service
        service_vulns = self.vulnerability_db.get(service_name, [])
        
        # Check each vulnerability
        for vuln in service_vulns:
            # Check if version matches
            if self._is_vulnerable_version(version, vuln["versions"]):
                vulnerabilities.append({
                    "cve": vuln["cve"],
                    "description": vuln["description"],
                    "severity": vuln["severity"],
                    "fixed_in": vuln.get("fixed_in", "Unknown")
                })
                
        return vulnerabilities
    
    def _is_vulnerable_version(self, version: str, vulnerable_versions: List[str]) -> bool:
        """
        Check if a version is in the list of vulnerable versions.
        Handles version ranges like "<2.4.10" or ">=1.0.0".
        
        Args:
            version: Version to check
            vulnerable_versions: List of vulnerable version strings or ranges
            
        Returns:
            True if version is vulnerable, False otherwise
        """
        from packaging import version as pkg_version
        
        # Convert version string to comparable object
        try:
            ver = pkg_version.parse(version)
        except:
            # If we can't parse the version, assume it's not vulnerable
            return False
        
        # Check each vulnerable version or range
        for v_version in vulnerable_versions:
            # Exact match
            if v_version == version:
                return True
                
            # Version range with comparison operator
            if v_version.startswith("<"):
                # Less than
                try:
                    compare_ver = pkg_version.parse(v_version[1:])
                    if ver < compare_ver:
                        return True
                except:
                    pass
            elif v_version.startswith("<="):
                # Less than or equal
                try:
                    compare_ver = pkg_version.parse(v_version[2:])
                    if ver <= compare_ver:
                        return True
                except:
                    pass
            elif v_version.startswith(">"):
                # Greater than
                try:
                    compare_ver = pkg_version.parse(v_version[1:])
                    if ver > compare_ver:
                        return True
                except:
                    pass
            elif v_version.startswith(">="):
                # Greater than or equal
                try:
                    compare_ver = pkg_version.parse(v_version[2:])
                    if ver >= compare_ver:
                        return True
                except:
                    pass
                    
        return False
    
    def display_service_info(self, service_info: Dict[str, Any]):
        """
        Display service identification information in a formatted table.
        
        Args:
            service_info: Service identification dictionary
        """
        # Create service info panel
        service_panel = Panel(
            f"[bold cyan]Service:[/bold cyan] {service_info['service_name']}\n"
            f"[bold cyan]Product:[/bold cyan] {service_info['product'] or 'Unknown'}\n"
            f"[bold cyan]Version:[/bold cyan] {service_info['version'] or 'Unknown'}\n",
            title="Service Identification",
            border_style="blue"
        )
        
        self.console.print(service_panel)
        
        # If we have a banner, display it
        if service_info["banner"]:
            banner_lines = service_info["banner"].split("\n")
            # Truncate if too long
            if len(banner_lines) > 10:
                banner_display = "\n".join(banner_lines[:10]) + "\n[dim]... (truncated)[/dim]"
            else:
                banner_display = service_info["banner"]
                
            banner_panel = Panel(
                banner_display,
                title="Service Banner",
                border_style="blue"
            )
            self.console.print(banner_panel)
            
        # If we have vulnerabilities, display them
        if service_info["vulnerabilities"]:
            vuln_table = Table(title="Potential Vulnerabilities")
            vuln_table.add_column("CVE", style="cyan")
            vuln_table.add_column("Severity", style="yellow")
            vuln_table.add_column("Description", style="white")
            vuln_table.add_column("Fixed In", style="green")
            
            for vuln in service_info["vulnerabilities"]:
                # Set color based on severity
                severity_color = "green"
                if vuln["severity"] == "Medium":
                    severity_color = "yellow"
                elif vuln["severity"] == "High":
                    severity_color = "orange"
                elif vuln["severity"] == "Critical":
                    severity_color = "red"
                    
                vuln_table.add_row(
                    vuln["cve"],
                    f"[{severity_color}]{vuln['severity']}[/{severity_color}]",
                    vuln["description"],
                    vuln["fixed_in"]
                )
                
            self.console.print(vuln_table)
        else:
            self.console.print("[green]No known vulnerabilities found for this service version.[/green]")
