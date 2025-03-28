import requests
import socket
import json
import os
import time
import subprocess
import folium
import webbrowser
from typing import Dict, List, Optional, Tuple, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn
import ipaddress

class IPGeolocation:
    """IP Geolocation module for NetworkScan Pro."""
    
    def __init__(self, console=None):
        """
        Initialize the IP Geolocation module.
        
        Args:
            console: Rich console object for display
        """
        # Use provided console or create a new one
        self.console = console if console else Console()
        self.cache_file = os.path.join(os.path.expanduser("~"), ".cache", "ip_geo_cache.json")
        self.cache = self._load_cache()
        
        # Initialize Folium (if available)
        self.has_folium = False
        try:
            import folium
            self.has_folium = True
        except ImportError:
            pass
            
        # Well-known anycast IPs and services
        self.anycast_ips = {
            # Public DNS services
            "8.8.8.8": "Google DNS",
            "8.8.4.4": "Google DNS",
            "1.1.1.1": "Cloudflare DNS",
            "1.0.0.1": "Cloudflare DNS",
            "9.9.9.9": "Quad9 DNS",
            "149.112.112.112": "Quad9 DNS",
            "208.67.222.222": "OpenDNS",
            "208.67.220.220": "OpenDNS",
            "64.6.64.6": "Verisign DNS",
            "64.6.65.6": "Verisign DNS",
            "185.228.168.9": "CleanBrowsing DNS",
            "185.228.169.9": "CleanBrowsing DNS",
            
            # CDN edge nodes
            "104.16.0.0/12": "Cloudflare Network",
            "198.41.128.0/17": "Cloudflare Network",
            "162.158.0.0/15": "Cloudflare Network",
            "172.64.0.0/13": "Cloudflare Network",
            "131.0.72.0/22": "Cloudflare Network",
            "13.32.0.0/15": "Amazon CloudFront",
            "13.224.0.0/14": "Amazon CloudFront",
            "143.204.0.0/16": "Amazon CloudFront",
            "99.84.0.0/16": "Amazon CloudFront",
            "151.101.0.0/16": "Fastly CDN",
            "23.235.32.0/20": "Fastly CDN",
            "117.18.232.0/21": "Fastly CDN",
            "199.27.72.0/21": "Akamai CDN",
            "23.64.0.0/14": "Akamai CDN",
            "104.64.0.0/10": "Akamai CDN",
            "184.24.0.0/13": "Akamai CDN",
            "72.246.0.0/15": "Akamai CDN",
            "96.16.0.0/15": "Akamai CDN",
            "69.192.0.0/16": "Akamai CDN",
            "204.79.197.0/24": "Microsoft Bing",
            "13.107.21.0/24": "Microsoft Services",
            "13.107.22.0/24": "Microsoft Services",
            "13.107.136.0/24": "Microsoft Services",
            "204.79.197.0/24": "Microsoft Services",
            "171.64.0.0/14": "Stanford University Network",
            
            # NTP servers
            "216.239.35.0": "Google NTP",
            "216.239.35.4": "Google NTP",
            "216.239.35.8": "Google NTP",
            "216.239.35.12": "Google NTP",
            "17.253.2.125": "Apple NTP",
            "17.253.14.125": "Apple NTP",
            "17.253.34.125": "Apple NTP",
            "17.253.66.125": "Apple NTP",
            "17.253.82.125": "Apple NTP",
            "17.253.106.125": "Apple NTP",
            
            # Root DNS servers
            "198.41.0.4": "Root DNS (A)",
            "199.9.14.201": "Root DNS (B)",
            "192.33.4.12": "Root DNS (C)",
            "199.7.91.13": "Root DNS (D)",
            "192.203.230.10": "Root DNS (E)",
            "192.5.5.241": "Root DNS (F)",
            "192.112.36.4": "Root DNS (G)",
            "198.97.190.53": "Root DNS (H)",
            "192.36.148.17": "Root DNS (I)",
            "192.58.128.30": "Root DNS (J)",
            "193.0.14.129": "Root DNS (K)",
            "199.7.83.42": "Root DNS (L)",
            "202.12.27.33": "Root DNS (M)"
        }
        
        # Known anycast AS numbers
        self.anycast_asns = [
            "AS13335",  # Cloudflare
            "AS15169",  # Google
            "AS16509",  # Amazon AWS
            "AS14618",  # Amazon AWS
            "AS16625",  # Akamai
            "AS32787",  # Akamai
            "AS12222",  # Akamai
            "AS20940",  # Akamai
            "AS35994",  # Akamai
            "AS34164",  # Akamai
            "AS21342",  # Akamai
            "AS21357",  # Akamai
            "AS20189",  # Akamai 
            "AS2906",   # Netflix
            "AS2914",   # NTT Communications
            "AS3356",   # Level 3 / Lumen
            "AS6939",   # Hurricane Electric
            "AS1299",   # Telia
            "AS174",    # Cogent
            "AS3257",   # GTT Communications
            "AS6461",   # Zayo
            "AS6762",   # Telecom Italia Sparkle
            "AS9002",   # RETN
            "AS9009",   # M247
            "AS36351",  # SoftLayer
            "AS15133",  # Verizon
            "AS54113",  # Fastly
            "AS396982", # Google Cloud
            "AS20473",  # Choopa LLC
            "AS6453",   # TATA Communications
            "AS209242", # Cloudflare WARP
        ]
        
        # Keywords that suggest anycast in organization names
        self.anycast_org_keywords = [
            "cdn", 
            "cloud",
            "edge",
            "akamai",
            "cloudflare", 
            "fastly", 
            "amazon", 
            "aws", 
            "microsoft",
            "azure",
            "google", 
            "tencent",
            "alibaba",
            "limelight",
            "verizon",
            "edgecast",
            "stackpath",
            "cachefly",
            "incapsula",
            "imperva",
            "level3",
            "lumen",
            "centurylink",
            "dyn",
            "oracle",
            "dns",
            "ntp",
            "content delivery",
            "distributed",
            "anycast"
        ]
        
    def _load_cache(self) -> Dict[str, Dict[str, Any]]:
        """Load the IP geolocation cache from disk."""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not load geolocation cache: {str(e)}[/yellow]")
            return {}
            
    def _save_cache(self) -> None:
        """Save the IP geolocation cache to disk."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not save geolocation cache: {str(e)}[/yellow]")

    def _get_ip_info(self, ip: str) -> Dict[str, Any]:
        """
        Get geolocation information for an IP address.
        
        Args:
            ip: The IP address to lookup
            
        Returns:
            dict: Geolocation data dictionary
        """
        # Check if we have this IP in cache
        if ip in self.cache:
            return self.cache[ip]
            
        # Select API to use - we have multiple options in case one fails
        # or for better accuracy
        api_endpoints = [
            # Primary API - ip-api.com (free, no key required)
            f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,district,zip,lat,lon,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
            
            # Fallback API - ipinfo.io (works without key but limited)
            f"https://ipinfo.io/{ip}/json"
        ]
        
        # Try each API until we get a successful response
        result = None
        error_messages = []
        
        for api_url in api_endpoints:
            try:
                response = requests.get(api_url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    
                    # Handle different API response formats
                    if "ipinfo.io" in api_url:
                        # Convert ipinfo.io format to our standard format
                        loc_parts = data.get('loc', '0,0').split(',')
                        result = {
                            'status': 'success',
                            'country': data.get('country', 'Unknown'),
                            'regionName': data.get('region', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'lat': float(loc_parts[0]) if len(loc_parts) > 0 else 0,
                            'lon': float(loc_parts[1]) if len(loc_parts) > 1 else 0,
                            'isp': data.get('org', 'Unknown'),
                            'org': data.get('org', 'Unknown'),
                            'as': data.get('asn', ''),
                            'query': ip,
                            'hosting': 'hosting' in data.get('company', {}).get('type', '').lower() if 'company' in data else False
                        }
                        break
                    elif data.get('status') == 'success':
                        # ip-api.com format (already matches our format)
                        result = data
                        break
                    elif 'error' not in data:
                        # Generic handling for other APIs that don't have an explicit status
                        result = {
                            'status': 'success',
                            'country': data.get('country', 'Unknown'),
                            'regionName': data.get('region', data.get('regionName', 'Unknown')),
                            'city': data.get('city', 'Unknown'),
                            'lat': data.get('latitude', data.get('lat', 0)),
                            'lon': data.get('longitude', data.get('lon', 0)),
                            'isp': data.get('isp', data.get('org', 'Unknown')),
                            'org': data.get('org', data.get('organization', 'Unknown')),
                            'as': data.get('as', data.get('asn', '')),
                            'query': ip
                        }
                        break
                else:
                    error_messages.append(f"API returned status code {response.status_code}")
            except requests.RequestException as e:
                error_messages.append(f"Request error: {str(e)}")
            except ValueError as e:
                error_messages.append(f"JSON parsing error: {str(e)}")
            except Exception as e:
                error_messages.append(f"Unexpected error: {str(e)}")
        
        # If all APIs failed, return an error
        if not result:
            error_msg = " | ".join(error_messages) if error_messages else "Unknown error"
            result = {
                'status': 'fail',
                'message': f"Could not get geolocation data: {error_msg}",
                'query': ip
            }
            
        # Cache the result
        self.cache[ip] = result
        self._save_cache()
        
        return result
    
    def _is_potential_anycast(self, ip_address: str, geo_data: Dict[str, Any]) -> bool:
        """
        Check if an IP address is likely an anycast IP.
        
        Args:
            ip_address: The IP address to check
            geo_data: Geolocation data for the IP
            
        Returns:
            bool: True if the IP is likely anycast, False otherwise
        """
        # Check if it's a known anycast IP
        if ip_address in self.anycast_ips:
            return True
        
        # Check if it falls within a known anycast IP range (CIDR notation)
        for cidr, _ in self.anycast_ips.items():
            if '/' in cidr:
                try:
                    network = ipaddress.ip_network(cidr)
                    if ipaddress.ip_address(ip_address) in network:
                        return True
                except ValueError:
                    # If CIDR parsing fails, just continue
                    continue
                    
        # Check AS number
        asn = geo_data.get('as', '')
        if any(known_asn in asn for known_asn in self.anycast_asns):
            return True
            
        # Check organization name for keywords that suggest a CDN or anycast service
        org = geo_data.get('org', '').lower()
        isp = geo_data.get('isp', '').lower()
        asname = geo_data.get('asname', '').lower()
        
        for keyword in self.anycast_org_keywords:
            if (keyword in org or keyword in isp or keyword in asname):
                return True
                
        # Check for hosting flags - these often indicate data centers that might host anycast services
        if geo_data.get('hosting', False) or geo_data.get('proxy', False):
            # More indicators that increase likelihood of anycast
            if any([
                'cdn' in org,
                'cdn' in isp,
                'cloud' in org,
                'cloud' in isp,
                'edge' in org, 
                'edge' in isp,
                'distributed' in org,
                'distributed' in isp
            ]):
                return True
                
        # Additional heuristics:
        # 1. Check if an IP resolves to many different domain names (reverse PTR records)
        reverse_dns = geo_data.get('reverse', '')
        if reverse_dns and any(keyword in reverse_dns.lower() for keyword in ['cdn', 'edge', 'cache', 'static']):
            return True
            
        # 2. Check if domain has unusual geolocation (common in anycast setups)
        country = geo_data.get('country', '')
        city = geo_data.get('city', '')
        
        # Major cloud/CDN hubs that often indicate anycast nodes
        anycast_hubs = [
            ('United States', 'Ashburn'),
            ('United States', 'San Jose'),
            ('United States', 'Seattle'),
            ('United States', 'Chicago'),
            ('United States', 'Dallas'),
            ('United States', 'Los Angeles'),
            ('United States', 'San Francisco'),
            ('United States', 'New York'),
            ('United States', 'Miami'),
            ('United States', 'Atlanta'),
            ('Germany', 'Frankfurt'),
            ('United Kingdom', 'London'),
            ('Japan', 'Tokyo'),
            ('Singapore', 'Singapore'),
            ('Australia', 'Sydney'),
            ('Brazil', 'São Paulo'),
            ('Netherlands', 'Amsterdam'),
            ('France', 'Paris'),
            ('India', 'Mumbai'),
            ('Ireland', 'Dublin'),
            ('Hong Kong', 'Hong Kong')
        ]
        
        # If IP is in a major cloud hub AND has hosting flags or cloud-related ASN/org
        if (country, city) in anycast_hubs:
            # Additional evidence that suggests anycast in major hubs
            if (geo_data.get('hosting', False) or 
                'cloud' in org or 'cdn' in org or 
                any(asn in geo_data.get('as', '') for asn in ['16509', '14618', '13335'])):
                return True
                
        return False
        
    def lookup_ip(self, ip: str, output_file: Optional[str] = None, open_map: bool = False) -> None:
        """
        Look up and display geolocation information for an IP address.
        
        Args:
            ip: The IP address to look up
            output_file: Optional HTML file to output the map to
            open_map: Whether to automatically open the map in a browser
        """
        self.console.print(f"Looking up geolocation information for [cyan]{ip}[/cyan]")
        
        # Resolve hostname to IP if needed
        try:
            socket.inet_aton(ip)  # Check if valid IP
        except socket.error:
            try:
                self.console.print(f"Resolving hostname [cyan]{ip}[/cyan] to IP address...")
                ip_addr = socket.gethostbyname(ip)
                self.console.print(f"Resolved [cyan]{ip}[/cyan] to [green]{ip_addr}[/green]")
                ip = ip_addr
            except socket.gaierror:
                self.console.print(f"[bold red]Error: Could not resolve hostname {ip}[/bold red]")
                return
        
        # Get geolocation data
        geo_data = self._get_ip_info(ip)
        
        if geo_data.get('status') != 'success':
            self.console.print(f"[bold red]Error looking up IP: {geo_data.get('message', 'Unknown error')}[/bold red]")
            return
        
        # Check if this is a potential anycast IP address
        is_anycast = self._is_potential_anycast(ip, geo_data)
        if is_anycast:
            known_service = self.anycast_ips.get(ip, "")
            anycast_msg = f"[bold yellow]⚠️ WARNING: This appears to be an anycast IP address{' (' + known_service + ')' if known_service else ''}.[/bold yellow]"
            self.console.print(anycast_msg)
            self.console.print("[yellow]Anycast IPs are announced from multiple locations worldwide.[/yellow]")
            self.console.print("[yellow]The geolocation shown may not represent the actual server you're connecting to.[/yellow]")
        
        # Create and display the geolocation table
        table = Table(title=f"Geolocation Information for {ip}", box=box.ROUNDED)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        # Add rows for various properties
        table.add_row("IP Address", geo_data.get('query', ip))
        table.add_row("Country", geo_data.get('country', 'Unknown'))
        table.add_row("Region", geo_data.get('regionName', 'Unknown'))
        table.add_row("City", geo_data.get('city', 'Unknown'))
        if geo_data.get('district'):
            table.add_row("District", geo_data.get('district'))
        if geo_data.get('zip'):
            table.add_row("ZIP Code", geo_data.get('zip'))
        table.add_row("Latitude", str(geo_data.get('lat', 'Unknown')))
        table.add_row("Longitude", str(geo_data.get('lon', 'Unknown')))
        table.add_row("ISP", geo_data.get('isp', 'Unknown'))
        table.add_row("Organization", geo_data.get('org', 'Unknown'))
        if geo_data.get('as'):
            table.add_row("AS Number", geo_data.get('as'))
        if geo_data.get('asname'):
            table.add_row("AS Name", geo_data.get('asname'))
        if geo_data.get('reverse'):
            table.add_row("Reverse DNS", geo_data.get('reverse'))
        table.add_row("Mobile", "Yes" if geo_data.get('mobile') else "No")
        table.add_row("Proxy/VPN", "Yes" if geo_data.get('proxy') else "No")
        table.add_row("Hosting/Data Center", "Yes" if geo_data.get('hosting') else "No")
        
        self.console.print(table)
        
        # Generate ASCII map visualization with IP location if no output file
        if not output_file:
            self._display_ascii_map(geo_data)
        else:
            # Generate HTML map
            self._generate_ip_map(geo_data, output_file)
            self.console.print(f"[green]Interactive map saved to: [bold]{output_file}[/bold][/green]")
            
            # Open the map if requested
            if open_map:
                self.open_html_map(output_file)
    
    def _display_ascii_map(self, geo_data: Dict[str, Any]) -> None:
        """
        Display an ASCII map with the IP location marked.
        
        Args:
            geo_data: Geolocation data dictionary
        """
        lat = geo_data.get('lat')
        lon = geo_data.get('lon')
        
        if not lat or not lon:
            self.console.print("[yellow]Could not generate map: Missing coordinates[/yellow]")
            return
            
        # World map in ASCII art (basic)
        ascii_map = [
            "                                                                               ",
            "                                                                               ",
            "     .        __..._                                     _,                    ",
            "    .     _,-'  -. `.          .           .          ,'/|                    ",
            "     `. ,'    .   \\ \\          |           |        ,' / |                    ",
            "      ,'     |`-._/ |          |   ,---.   |       /  /  '                    ",
            "     /      .'     -`.       .-|--/     \\--|-.    /  /--\"                     ",
            "    /      /      /  `       `-'  \\     /  `-'   /  /                         ",
            "    |     |    ,-/            |         |       /  /                          ",
            "   .'     \\   /,'             |         |      /  /                           ",
            "   |       `-+                |         |     /  /                            ",
            "  .'        J                 |         |    /  /                             ",
            "  |          L                |         |   /  /                              ",
            " .'          |                |         |  /  /                               ",
            " |         J                  |         | /  /                                ",
            " |_        |                  |         |/  /                                 ",
            "J L        \\                 /           /  /                                 ",
            "| |         \\               /|          /  /                                  ",
            "L_J         |        _     / |         /  /                                   ",
            " L_L        |      ,' `.  /  |        /  /                                    ",
            " |  \\      /      /     `/   /       /  /                                     ",
            " L__\\    ,'      /     ,'   |      |`  /                                      ",
            "  \\__/   /      |    ,'     |      |   /                                      ",
            "        |      .'  ,'      /       /  /                                       ",
            "         \\     /   /      /       /  /                                        ",
            "          `.  /   /      /       /  /                                         ",
            "            `\"   /      |       /  /                                          ",
            "                /       |      /  /                                           ",
            "               /        \\     /  /                                            ",
            "              /          \\   /  /                                             ",
            "             /            \\ /  /                                              ",
            "            /              '  /                                               ",
            "           /               | /                                                ",
            "          /                L/                                                 ",
            "         /                                                                    ",
            "        /                                                                     ",
            "                                                                               "
        ]
        
        # Very approximate projection to place a marker on the ASCII map
        marker_row = int((90 - lat) / 180 * (len(ascii_map) - 1))
        marker_col = int((lon + 180) / 360 * (len(ascii_map[0]) - 1))
        
        # Place marker at the coordinates
        map_with_marker = ascii_map.copy()
        if 0 <= marker_row < len(map_with_marker) and 0 <= marker_col < len(map_with_marker[0]):
            row = map_with_marker[marker_row]
            map_with_marker[marker_row] = row[:marker_col] + "X" + row[marker_col + 1:]
        
        # Display the map
        self.console.print(Panel(
            "\n".join(map_with_marker),
            title=f"Location of {geo_data.get('query')} ({geo_data.get('country')})",
            border_style="blue"
        ))
    
    def _generate_ip_map(self, geo_data: Dict[str, Any], output_file: str) -> None:
        """
        Generate an interactive HTML map with IP location.
        
        Args:
            geo_data: Geolocation data dictionary
            output_file: Path to save the HTML map
        """
        lat = geo_data.get('lat')
        lon = geo_data.get('lon')
        ip = geo_data.get('query', '')
        
        if not lat or not lon:
            self.console.print("[yellow]Could not generate map: Missing coordinates[/yellow]")
            return
        
        # Check if this is a potential anycast IP
        is_anycast = self._is_potential_anycast(ip, geo_data)
        
        # Create a map centered on the IP location
        m = folium.Map(location=[lat, lon], zoom_start=10)
        
        # Add a marker for the IP with a popup containing information
        popup_html = f"""
        <h3>{ip}</h3>
        <b>Country:</b> {geo_data.get('country', 'Unknown')}<br>
        <b>Region:</b> {geo_data.get('regionName', 'Unknown')}<br>
        <b>City:</b> {geo_data.get('city', 'Unknown')}<br>
        <b>ISP:</b> {geo_data.get('isp', 'Unknown')}<br>
        <b>Organization:</b> {geo_data.get('org', 'Unknown')}<br>
        """
        
        # Add anycast warning if needed
        if is_anycast:
            known_service = self.anycast_ips.get(ip, "")
            service_info = f" ({known_service})" if known_service else ""
            popup_html += f"""
            <hr>
            <div style="color: orange; font-weight: bold;">⚠️ WARNING: This appears to be an anycast IP address{service_info}.</div>
            <div style="color: orange;">Anycast IPs are announced from multiple locations worldwide.</div>
            <div style="color: orange;">The geolocation shown may not represent the actual server you're connecting to.</div>
            """
        
        # Use different icon for anycast IPs
        icon_color = 'orange' if is_anycast else 'red'
        icon_type = 'warning-sign' if is_anycast else 'info-sign'
        
        folium.Marker(
            location=[lat, lon],
            popup=folium.Popup(popup_html, max_width=300),
            tooltip=f"{ip} - {geo_data.get('org', geo_data.get('isp', 'Unknown'))}",
            icon=folium.Icon(color=icon_color, icon=icon_type)
        ).add_to(m)
        
        # Add a disclaimer note for anycast IPs
        if is_anycast:
            disclaimer_html = """
            <div style="position: fixed; bottom: 10px; left: 10px; z-index: 1000; 
                        background-color: rgba(255, 255, 255, 0.8); padding: 10px; border-radius: 5px; 
                        box-shadow: 0 0 10px rgba(0,0,0,0.1); max-width: 300px;">
                <strong style="color: orange;">⚠️ Anycast IP Warning</strong><br>
                This IP address is served from multiple physical locations worldwide.<br>
                The shown location may not be the actual server responding to your requests.
            </div>
            """
            m.get_root().html.add_child(folium.Element(disclaimer_html))
        
        # Save the map to an HTML file
        m.save(output_file)
    
    def trace_path(self, target: str) -> None:
        """
        Trace route to target with geolocation info for each hop.
        
        Args:
            target: The domain or IP address to trace
        """
        if not target:
            self.console.print("[red]Error: Target cannot be empty[/red]")
            return
            
        # Validate and convert domain to IP if needed
        try:
            if not self._is_valid_ip(target):
                ip = socket.gethostbyname(target)
                self.console.print(f"Resolved {target} to IP: {ip}")
                target_for_display = f"{target} ({ip})"
            else:
                ip = target
                target_for_display = target
        except socket.gaierror:
            self.console.print(f"[red]Error: Could not resolve hostname: {target}[/red]")
            return
            
        self.console.print(f"\n[bold blue]Tracing route to {target_for_display} with geolocation...[/bold blue]")
        
        # Create a status display
        with self.console.status("[bold green]Running traceroute...") as status:
            try:
                # Run traceroute (Windows uses tracert, Linux/macOS uses traceroute)
                cmd = 'tracert' if os.name == 'nt' else 'traceroute'
                if os.name == 'nt':
                    process = subprocess.Popen(['tracert', '-d', '-h', '30', ip], 
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                else:
                    process = subprocess.Popen(['traceroute', '-n', '-m', '30', ip],
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Parse traceroute output
                hops = []
                hop_ips = []
                
                status.update("[bold green]Collecting hop data...[/bold green]")
                for line in process.stdout:
                    if os.name == 'nt':
                        # Windows tracert format
                        if "Tracing route" in line or "over a maximum" in line or "ms" not in line:
                            continue
                        parts = line.strip().split()
                        try:
                            hop_num = int(parts[0])
                            # Find IP in the line (Windows format varies)
                            ip_addr = None
                            for part in parts:
                                if self._is_valid_ip(part):
                                    ip_addr = part
                                    break
                            
                            if ip_addr:
                                hops.append((hop_num, ip_addr))
                                hop_ips.append(ip_addr)
                        except (ValueError, IndexError):
                            continue
                    else:
                        # Linux/macOS traceroute format
                        if "traceroute to" in line:
                            continue
                        parts = line.strip().split()
                        try:
                            hop_num = int(parts[0])
                            ip_addr = parts[1]
                            if ip_addr == '*' and len(parts) > 2 and self._is_valid_ip(parts[2]):
                                ip_addr = parts[2]
                            
                            if self._is_valid_ip(ip_addr):
                                hops.append((hop_num, ip_addr))
                                hop_ips.append(ip_addr)
                        except (ValueError, IndexError):
                            continue
                
                # Lookup geolocation for all IPs at once
                status.update("[bold green]Looking up geolocation data for hops...[/bold green]")
                geo_data = {}
                for ip_addr in hop_ips:
                    if ip_addr not in geo_data and self._is_valid_ip(ip_addr):
                        geo_data[ip_addr] = self._get_ip_info(ip_addr)
                        time.sleep(0.1)  # Small delay to avoid API rate limits
                
                # Display traceroute results with geolocation
                status.update("[bold green]Creating visualization...[/bold green]")
                if hops:
                    table = Table(show_header=True, header_style="bold magenta")
                    table.add_column("Hop", style="dim", width=4)
                    table.add_column("IP Address", width=15)
                    table.add_column("Location", width=30)
                    table.add_column("ISP/Organization", width=30)
                    table.add_column("Anycast", width=6)
                    
                    # Create an interactive map for the trace
                    output_file = os.path.join(os.getcwd(), 'tracemap.html')
                    m = folium.Map(tiles="CartoDB positron")
                    points = []
                    lines = []
                    anycast_detected = False
                    
                    # Add hops to the table and map
                    for hop_num, ip_addr in hops:
                        location = ""
                        isp = ""
                        is_anycast = False
                        
                        if ip_addr in geo_data and geo_data[ip_addr].get('status') == 'success':
                            hop_geo = geo_data[ip_addr]
                            
                            # Check if this is an anycast IP
                            is_anycast = self._is_potential_anycast(ip_addr, hop_geo)
                            anycast_detected = anycast_detected or is_anycast
                            
                            # Get location info
                            country = hop_geo.get('country', 'Unknown')
                            city = hop_geo.get('city', '')
                            region = hop_geo.get('regionName', '')
                            
                            if city and region:
                                location = f"{city}, {region}, {country}"
                            elif city:
                                location = f"{city}, {country}"
                            elif region:
                                location = f"{region}, {country}"
                            else:
                                location = country
                                
                            # Get ISP/Organization info
                            org = hop_geo.get('org', '')
                            isp = hop_geo.get('isp', '')
                            asn = hop_geo.get('as', '')
                            
                            if org and isp and org != isp:
                                isp_org = f"{isp} / {org}"
                            elif org:
                                isp_org = org
                            elif isp:
                                isp_org = isp
                            elif asn:
                                isp_org = asn
                            else:
                                isp_org = "Unknown"
                                
                            # Add to table
                            row_style = "yellow" if is_anycast else None
                            anycast_marker = "[yellow]Yes[/yellow]" if is_anycast else "No"
                            table.add_row(str(hop_num), ip_addr, location, isp_org, anycast_marker, style=row_style)
                            
                            # Add to map if coordinates are available
                            if 'lat' in hop_geo and 'lon' in hop_geo:
                                lat, lon = hop_geo['lat'], hop_geo['lon']
                                points.append((lat, lon))
                                self._add_hop_to_map(m, hop_num, ip_addr, hop_geo, is_anycast)
                        else:
                            table.add_row(str(hop_num), ip_addr, "Unknown location", "Unknown provider", "?")
                    
                    # Add lines connecting the points
                    if len(points) > 1:
                        folium.PolyLine(points, color="red", weight=2, opacity=0.8).add_to(m)
                    
                    # Fit map to all markers
                    if points:
                        m.fit_bounds(points)
                    
                    # Add disclaimer if anycast detected
                    if anycast_detected:
                        disclaimer_html = """
                        <div style="position: fixed; bottom: 10px; left: 10px; z-index: 1000; 
                                    background-color: rgba(255, 255, 255, 0.8); padding: 10px; border-radius: 5px; 
                                    box-shadow: 0 0 10px rgba(0,0,0,0.1); max-width: 300px;">
                            <strong style="color: orange;">⚠️ Anycast IP Warning</strong><br>
                            One or more hops on this route are anycast IPs, served from multiple physical locations worldwide.<br>
                            The shown locations may not represent the actual network path of your packets.
                        </div>
                        """
                        m.get_root().html.add_child(folium.Element(disclaimer_html))
                    
                    # Save the map
                    m.save(output_file)
                    
                    self.console.print(table)
                    self.console.print(f"\n[green]Interactive map saved to:[/green] {output_file}")
                    
                    # Display ASCII map of the trace with anycast warnings
                    self._display_ascii_tracemap(hops, geo_data)
                    
                    # Offer to open the map in a browser
                    self._open_map_in_browser(output_file)
                else:
                    self.console.print("[yellow]No valid hops found in traceroute output[/yellow]")
                    
            except Exception as e:
                self.console.print(f"[red]Error running traceroute: {str(e)}[/red]")

    def _add_hop_to_map(self, map_obj, hop_num, ip_addr, geo_data, is_anycast=False):
        """
        Add a hop marker to the map.
        
        Args:
            map_obj: Folium map object
            hop_num: Hop number
            ip_addr: IP address
            geo_data: Geolocation data
            is_anycast: Whether this is an anycast IP
        """
        lat = geo_data.get('lat')
        lon = geo_data.get('lon')
        
        if not lat or not lon:
            return
            
        city = geo_data.get('city', 'Unknown city')
        country = geo_data.get('country', 'Unknown country')
        isp = geo_data.get('isp', 'Unknown ISP')
        org = geo_data.get('org', '')
        
        popup_html = f"""
        <h3>Hop {hop_num}: {ip_addr}</h3>
        <b>Country:</b> {geo_data.get('country', 'Unknown')}<br>
        <b>Region:</b> {geo_data.get('regionName', 'Unknown')}<br>
        <b>City:</b> {geo_data.get('city', 'Unknown')}<br>
        <b>ISP:</b> {geo_data.get('isp', 'Unknown')}<br>
        <b>Organization:</b> {geo_data.get('org', 'Unknown')}<br>
        """
        
        # Add anycast warning if needed
        if is_anycast:
            known_service = self.anycast_ips.get(ip_addr, "")
            service_info = f" ({known_service})" if known_service else ""
            popup_html += f"""
            <hr>
            <div style="color: orange; font-weight: bold;">⚠️ WARNING: This appears to be an anycast IP address{service_info}.</div>
            <div style="color: orange;">Anycast IPs are announced from multiple locations worldwide.</div>
            <div style="color: orange;">The geolocation shown may not represent the actual server location.</div>
            """
        
        # Different style for start, end and anycast IPs
        if hop_num == 1:
            icon = folium.Icon(color='green', icon='home')
        elif is_anycast:
            icon = folium.Icon(color='orange', icon='warning-sign')
        else:
            icon = folium.Icon(color='blue', icon='info-sign')
            
        folium.Marker(
            location=[lat, lon],
            popup=folium.Popup(popup_html, max_width=300),
            tooltip=f"Hop {hop_num}: {ip_addr} ({city}, {country})",
            icon=icon
        ).add_to(map_obj)
    
    def open_html_map(self, output_file: str) -> None:
        """
        Open the generated HTML map in the default web browser.
        
        Args:
            output_file: Path to the HTML file to open
        """
        if not os.path.exists(output_file):
            self.console.print(f"[bold red]Error: Map file not found: {output_file}[/bold red]")
            return
            
        try:
            # Convert to absolute path to ensure proper opening
            abs_path = os.path.abspath(output_file)
            
            # Open the file in the default web browser
            webbrowser.open('file://' + abs_path, new=2)
            self.console.print(f"[green]Map opened in your default web browser[/green]")
        except Exception as e:
            self.console.print(f"[bold red]Error opening map: {str(e)}[/bold red]")
    
    def _is_valid_ip(self, ip: str) -> bool:
        """
        Check if a string is a valid IP address.
        
        Args:
            ip: String to check
            
        Returns:
            True if valid IP, False otherwise
        """
        try:
            # Handle special cases like "*" in traceroute
            if ip == '*' or len(ip) < 7:  # Minimum valid IP is 1.1.1.1
                return False
                
            # Try to pack the IP address
            socket.inet_aton(ip)
            
            # Extra check: should have 3 dots
            if ip.count('.') != 3:
                return False
                
            return True
        except:
            return False 