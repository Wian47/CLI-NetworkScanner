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

class IPGeolocation:
    """IP Geolocation module for NetworkScan Pro."""
    
    def __init__(self, console: Console):
        """Initialize the IP Geolocation module."""
        self.console = console
        # Free API with rate limiting (45 requests per minute)
        self.api_url = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,district,zip,lat,lon,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        # Create cache directory if it doesn't exist
        os.makedirs('.cache', exist_ok=True)
        self.cache_file = os.path.join('.cache', 'ip_geo_cache.json')
        self.cache = self._load_cache()
        
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
            ip: The IP address to look up
            
        Returns:
            Dictionary with geolocation information
        """
        # Check if we have cached data
        if ip in self.cache:
            return self.cache[ip]
            
        try:
            response = requests.get(self.api_url.format(ip=ip), timeout=5)
            data = response.json()
            
            if data.get('status') == 'success':
                # Cache the result
                self.cache[ip] = data
                self._save_cache()
                # Add a small delay to avoid API rate limiting
                time.sleep(0.5)
                return data
            else:
                return {"status": "failed", "message": data.get("message", "Unknown error")}
        except Exception as e:
            return {"status": "failed", "message": str(e)}
    
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
        
        if not lat or not lon:
            self.console.print("[yellow]Could not generate map: Missing coordinates[/yellow]")
            return
        
        # Create a map centered on the IP location
        m = folium.Map(location=[lat, lon], zoom_start=10)
        
        # Add a marker for the IP with a popup containing information
        popup_html = f"""
        <h3>{geo_data.get('query')}</h3>
        <b>Country:</b> {geo_data.get('country', 'Unknown')}<br>
        <b>Region:</b> {geo_data.get('regionName', 'Unknown')}<br>
        <b>City:</b> {geo_data.get('city', 'Unknown')}<br>
        <b>ISP:</b> {geo_data.get('isp', 'Unknown')}<br>
        <b>Organization:</b> {geo_data.get('org', 'Unknown')}<br>
        """
        
        folium.Marker(
            location=[lat, lon],
            popup=folium.Popup(popup_html, max_width=300),
            tooltip=f"{geo_data.get('query')} - {geo_data.get('org', geo_data.get('isp', 'Unknown'))}",
            icon=folium.Icon(color='red', icon='info-sign')
        ).add_to(m)
        
        # Save the map to an HTML file
        m.save(output_file)
    
    def trace_path(self, target: str, output_file: Optional[str] = None, open_map: bool = False) -> None:
        """
        Trace network path to a target and display geolocation for each hop.
        
        Args:
            target: The target hostname or IP address
            output_file: Optional HTML file to output the map to
            open_map: Whether to automatically open the map in a browser
        """
        self.console.print(f"Tracing path to [cyan]{target}[/cyan] with geolocation...")
        
        # Resolve hostname to IP if needed
        try:
            socket.inet_aton(target)  # Check if valid IP
            target_ip = target
        except socket.error:
            try:
                self.console.print(f"Resolving hostname [cyan]{target}[/cyan] to IP address...")
                target_ip = socket.gethostbyname(target)
                self.console.print(f"Resolved [cyan]{target}[/cyan] to [green]{target_ip}[/green]")
            except socket.gaierror:
                self.console.print(f"[bold red]Error: Could not resolve hostname {target}[/bold red]")
                return
        
        # Create table for trace results
        table = Table(title=f"Network Path to {target}", box=box.ROUNDED)
        table.add_column("Hop", style="cyan", justify="right")
        table.add_column("IP Address", style="green")
        table.add_column("Host", style="blue")
        table.add_column("Location", style="cyan")
        table.add_column("ISP/Org", style="magenta")
        table.add_column("Latency", style="bright_cyan", justify="right")
        
        # Platform-specific traceroute command
        if os.name == 'nt':  # Windows
            command = ['tracert', '-d', '-h', '30', target]
        else:  # Unix/Linux/Mac
            command = ['traceroute', '-n', '-m', '30', target]
            
        try:
            # Run traceroute
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold green]Running traceroute - this may take a minute...[/bold green]"),
                console=self.console
            ) as progress:
                task = progress.add_task("Tracing...", total=None)
                
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Initialize variables for parsing output
                hop_count = 0
                hops = []
                
                # Process output line by line
                for line in process.stdout:
                    # Different parsing for Windows and Unix
                    if os.name == 'nt':  # Windows
                        if not line.startswith('  '):
                            continue
                            
                        parts = line.strip().split()
                        if len(parts) >= 1:
                            try:
                                hop_num = int(parts[0])
                                hop_count = hop_num
                                
                                # Extract IP address
                                ip_addr = None
                                for part in parts:
                                    if self._is_valid_ip(part):
                                        ip_addr = part
                                        break
                                
                                # Extract latency
                                latency = "N/A"
                                for i, part in enumerate(parts):
                                    if part == 'ms' and i > 0:
                                        latency = parts[i-1] + " ms"
                                        break
                                
                                if ip_addr:
                                    hops.append({
                                        'hop': hop_num,
                                        'ip': ip_addr,
                                        'latency': latency
                                    })
                            except (ValueError, IndexError):
                                pass
                    else:  # Unix/Linux/Mac
                        parts = line.strip().split()
                        if len(parts) >= 1:
                            try:
                                hop_num = int(parts[0])
                                hop_count = hop_num
                                
                                # Extract IP address and latency
                                ip_addr = parts[1] if len(parts) > 1 and self._is_valid_ip(parts[1]) else None
                                latency = parts[2] + " ms" if len(parts) > 2 else "N/A"
                                
                                if ip_addr:
                                    hops.append({
                                        'hop': hop_num,
                                        'ip': ip_addr,
                                        'latency': latency
                                    })
                            except (ValueError, IndexError):
                                pass
            
            # Get geolocation data for each hop
            self.console.print("Retrieving geolocation information for each hop...")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold green]Getting geolocation data...[/bold green]"),
                console=self.console
            ) as progress:
                geolocation_task = progress.add_task("Processing...", total=len(hops))
                
                for hop in hops:
                    ip = hop['ip']
                    if ip == '*' or not self._is_valid_ip(ip):
                        hop['geo'] = {'status': 'failed'}
                        continue
                        
                    hop['geo'] = self._get_ip_info(ip)
                    progress.update(geolocation_task, advance=1)
                    
                    # Try to get hostname
                    try:
                        hop['host'] = socket.getfqdn(ip)
                        if hop['host'] == ip:
                            hop['host'] = ''
                    except:
                        hop['host'] = ''
            
            # Add data to table
            for hop in hops:
                geo = hop['geo']
                if geo.get('status') == 'success':
                    location = f"{geo.get('city', '')}, {geo.get('regionName', '')}, {geo.get('country', '')}"
                    location = location.replace(", ,", ",").strip(" ,")
                    isp_org = geo.get('org', geo.get('isp', ''))
                else:
                    location = ""
                    isp_org = ""
                    
                ip_display = hop['ip'] if hop['ip'] != '*' else "*"
                table.add_row(
                    str(hop['hop']),
                    ip_display,
                    hop.get('host', ''),
                    location,
                    isp_org,
                    hop['latency']
                )
            
            # Display table
            self.console.print(table)
            
            # Create map visualization based on output type
            if not output_file:
                # Create a world map with hop locations in ASCII
                self._display_path_map(hops)
            else:
                # Generate interactive HTML map
                self._generate_path_map(hops, target, output_file)
                self.console.print(f"[green]Interactive map saved to: [bold]{output_file}[/bold][/green]")
            
            # Open the map if requested
            if open_map:
                self.open_html_map(output_file)
            
        except Exception as e:
            self.console.print(f"[bold red]Error during traceroute: {str(e)}[/bold red]")
    
    def _display_path_map(self, hops: List[Dict[str, Any]]) -> None:
        """
        Display an ASCII map with the path plotted.
        
        Args:
            hops: List of hop dictionaries with geolocation data
        """
        # World map in ASCII art
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
        
        # Create a working copy of the map
        map_with_path = ascii_map.copy()
        
        # Plot each hop with valid geolocation
        for hop_idx, hop in enumerate(hops):
            geo = hop.get('geo', {})
            if geo.get('status') != 'success':
                continue
                
            lat = geo.get('lat')
            lon = geo.get('lon')
            
            if not lat or not lon:
                continue
                
            # Calculate position on ASCII map
            marker_row = int((90 - lat) / 180 * (len(map_with_path) - 1))
            marker_col = int((lon + 180) / 360 * (len(map_with_path[0]) - 1))
            
            # Place marker at the coordinates
            if 0 <= marker_row < len(map_with_path) and 0 <= marker_col < len(map_with_path[0]):
                row = map_with_path[marker_row]
                
                # Use different markers for source, intermediate hops, and destination
                if hop_idx == 0:  # Source
                    marker = "S"
                elif hop_idx == len(hops) - 1:  # Destination
                    marker = "D"
                else:  # Intermediate hop
                    # Use hop number for intermediate hops if space allows
                    if hop.get('hop', 0) < 10:
                        marker = str(hop.get('hop'))
                    else:
                        marker = "+"
                
                map_with_path[marker_row] = row[:marker_col] + marker + row[marker_col + 1:]
        
        # Display the map
        self.console.print(Panel(
            "\n".join(map_with_path),
            title="Network Path Visualization",
            border_style="blue"
        ))
        
        # Add a legend
        self.console.print("Legend: S = Source, + = Intermediate Hop, D = Destination")
    
    def _generate_path_map(self, hops: List[Dict[str, Any]], target: str, output_file: str) -> None:
        """
        Generate an interactive HTML map with the traceroute path.
        
        Args:
            hops: List of hop dictionaries with geolocation data
            target: Target hostname or IP address
            output_file: Path to save the HTML map
        """
        # Find all valid hops with geolocation data
        valid_hops = []
        for hop in hops:
            geo = hop.get('geo', {})
            if geo.get('status') == 'success' and geo.get('lat') and geo.get('lon'):
                valid_hops.append(hop)
        
        if not valid_hops:
            self.console.print("[yellow]Could not generate map: No valid geolocation data[/yellow]")
            return
        
        # Get source and destination hops for the center of the map
        destination_hop = valid_hops[-1] if valid_hops else None
        
        # Create a map centered on the destination or the middle of the path
        if destination_hop and destination_hop['geo'].get('lat') and destination_hop['geo'].get('lon'):
            center_lat = destination_hop['geo'].get('lat')
            center_lon = destination_hop['geo'].get('lon')
        else:
            # Use center of valid points
            center_lat = sum(h['geo'].get('lat', 0) for h in valid_hops) / len(valid_hops)
            center_lon = sum(h['geo'].get('lon', 0) for h in valid_hops) / len(valid_hops)
        
        # Create the map
        m = folium.Map(location=[center_lat, center_lon], zoom_start=4)
        
        # Add markers for each hop
        coordinates = []
        for hop_idx, hop in enumerate(valid_hops):
            geo = hop['geo']
            lat = geo.get('lat')
            lon = geo.get('lon')
            
            if not lat or not lon:
                continue
                
            coordinates.append([lat, lon])
            
            # Prepare the popup content
            location = f"{geo.get('city', '')}, {geo.get('regionName', '')}, {geo.get('country', '')}"
            location = location.replace(", ,", ",").strip(" ,")
            
            popup_html = f"""
            <h3>Hop {hop.get('hop')} - {hop.get('ip')}</h3>
            <b>Location:</b> {location}<br>
            <b>ISP/Org:</b> {geo.get('org', geo.get('isp', 'Unknown'))}<br>
            <b>Latency:</b> {hop.get('latency', 'N/A')}<br>
            <b>Hostname:</b> {hop.get('host', 'Unknown')}<br>
            """
            
            # Determine the marker color and icon
            if hop_idx == 0:  # Source
                color = 'green'
                marker_icon = 'home'
                tooltip = "Source"
            elif hop_idx == len(valid_hops) - 1:  # Destination
                color = 'red'
                marker_icon = 'flag'
                tooltip = f"Destination: {target}"
            else:  # Intermediate hop
                color = 'blue'
                marker_icon = 'exchange'
                tooltip = f"Hop {hop.get('hop')}"
            
            # Add the marker
            folium.Marker(
                location=[lat, lon],
                popup=folium.Popup(popup_html, max_width=300),
                tooltip=tooltip,
                icon=folium.Icon(color=color, icon=marker_icon)
            ).add_to(m)
        
        # Add a line connecting all the hops
        if len(coordinates) > 1:
            folium.PolyLine(
                coordinates,
                color="red",
                weight=2,
                opacity=0.7,
                tooltip="Network Path"
            ).add_to(m)
        
        # Add a title to the map
        title_html = f'''
            <h3 align="center" style="font-size:16px"><b>Network Path to {target}</b></h3>
        '''
        m.get_root().html.add_child(folium.Element(title_html))
        
        # Save the map to an HTML file
        m.save(output_file)
    
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