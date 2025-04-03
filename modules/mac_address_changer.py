import re
import random
import subprocess
import platform
import time
from typing import Dict, List, Optional, Tuple, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

class MACAddressChanger:
    """MAC address changer module for NetworkScan Pro."""
    
    def __init__(self, console: Console = None):
        """Initialize the MAC address changer."""
        self.console = console or Console()
        self.original_macs = {}  # Store original MAC addresses
        
    def get_interfaces(self) -> List[Dict[str, str]]:
        """
        Get a list of network interfaces.
        
        Returns:
            List of dictionaries with interface information
        """
        interfaces = []
        system = platform.system()
        
        try:
            if system == "Windows":
                # Use PowerShell to get network interfaces on Windows
                output = subprocess.check_output(
                    ["powershell", "-Command", "Get-NetAdapter | Select-Object Name, MacAddress, Status | ConvertTo-Csv -NoTypeInformation"],
                    text=True
                )
                
                # Parse the CSV output
                lines = output.strip().split('\n')
                if len(lines) > 1:  # Skip header
                    headers = lines[0].strip('"').split('","')
                    for line in lines[1:]:
                        values = line.strip('"').split('","')
                        if len(values) >= 3:
                            interface = {
                                "name": values[0],
                                "mac": values[1].replace('-', ':'),
                                "status": values[2]
                            }
                            interfaces.append(interface)
                            
            elif system in ["Linux", "Darwin"]:  # Linux or macOS
                if system == "Linux":
                    # Use ip command on Linux
                    output = subprocess.check_output(["ip", "link", "show"], text=True)
                    
                    # Parse the output
                    for line in output.split('\n'):
                        if ': ' in line:
                            # Extract interface name
                            match = re.search(r'\d+: (\w+):', line)
                            if match:
                                name = match.group(1)
                                
                                # Skip loopback
                                if name == 'lo':
                                    continue
                                    
                                # Extract status
                                status = "UP" if "UP" in line else "DOWN"
                                
                                # Get MAC address from the next line
                                mac_line = output.split('\n')[output.split('\n').index(line) + 1]
                                mac_match = re.search(r'link/\w+ ([0-9a-f:]+)', mac_line)
                                
                                if mac_match:
                                    mac = mac_match.group(1)
                                    interfaces.append({
                                        "name": name,
                                        "mac": mac,
                                        "status": status
                                    })
                                    
                elif system == "Darwin":  # macOS
                    # Use ifconfig on macOS
                    output = subprocess.check_output(["ifconfig"], text=True)
                    
                    # Parse the output
                    current_interface = None
                    for line in output.split('\n'):
                        if line and not line.startswith('\t'):
                            # New interface
                            match = re.search(r'^(\w+):', line)
                            if match:
                                current_interface = match.group(1)
                                # Skip loopback
                                if current_interface == 'lo0':
                                    current_interface = None
                                    
                        elif current_interface and 'ether ' in line:
                            # MAC address line
                            mac_match = re.search(r'ether ([0-9a-f:]+)', line)
                            if mac_match:
                                mac = mac_match.group(1)
                                status = "UP" if "UP" in output.split(current_interface + ':')[1].split('\n')[0] else "DOWN"
                                interfaces.append({
                                    "name": current_interface,
                                    "mac": mac,
                                    "status": status
                                })
                                current_interface = None
                                
        except Exception as e:
            self.console.print(f"[bold red]Error getting network interfaces: {str(e)}[/bold red]")
            
        return interfaces
    
    def display_interfaces(self) -> Optional[List[Dict[str, str]]]:
        """
        Display available network interfaces and return them.
        
        Returns:
            List of interface dictionaries or None if no interfaces found
        """
        interfaces = self.get_interfaces()
        
        if not interfaces:
            self.console.print("[bold red]No network interfaces found.[/bold red]")
            return None
            
        # Create a table to display interfaces
        table = Table(title="Network Interfaces")
        table.add_column("#", style="cyan", justify="right")
        table.add_column("Interface", style="green")
        table.add_column("MAC Address", style="yellow")
        table.add_column("Status", style="magenta")
        
        for i, interface in enumerate(interfaces, 1):
            status_color = "green" if interface["status"] == "UP" else "red"
            table.add_row(
                str(i),
                interface["name"],
                interface["mac"],
                f"[{status_color}]{interface['status']}[/{status_color}]"
            )
            
        self.console.print(table)
        return interfaces
    
    def change_mac(self, interface_name: str, new_mac: Optional[str] = None) -> bool:
        """
        Change the MAC address of a network interface.
        
        Args:
            interface_name: Name of the interface to change
            new_mac: New MAC address (if None, a random MAC will be generated)
            
        Returns:
            True if successful, False otherwise
        """
        system = platform.system()
        
        # Generate a random MAC if none provided
        if not new_mac:
            new_mac = self._generate_random_mac()
            
        # Validate MAC address format
        if not self._validate_mac(new_mac):
            self.console.print(f"[bold red]Invalid MAC address format: {new_mac}[/bold red]")
            return False
            
        # Store original MAC if not already stored
        if interface_name not in self.original_macs:
            interfaces = self.get_interfaces()
            for interface in interfaces:
                if interface["name"] == interface_name:
                    self.original_macs[interface_name] = interface["mac"]
                    break
                    
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Changing MAC address..."),
                console=self.console
            ) as progress:
                progress.add_task("Changing...", total=None)
                
                if system == "Windows":
                    # Windows requires registry changes and adapter disable/enable
                    # First, disable the adapter
                    subprocess.run(
                        ["powershell", "-Command", f"Disable-NetAdapter -Name '{interface_name}' -Confirm:$false"],
                        check=True
                    )
                    
                    # Change the MAC address
                    subprocess.run(
                        ["powershell", "-Command", 
                         f"Set-NetAdapter -Name '{interface_name}' -MacAddress '{new_mac.replace(':', '')}' -Confirm:$false"],
                        check=True
                    )
                    
                    # Re-enable the adapter
                    subprocess.run(
                        ["powershell", "-Command", f"Enable-NetAdapter -Name '{interface_name}' -Confirm:$false"],
                        check=True
                    )
                    
                elif system == "Linux":
                    # Linux uses ip link set
                    # First, bring the interface down
                    subprocess.run(
                        ["ip", "link", "set", "dev", interface_name, "down"],
                        check=True
                    )
                    
                    # Change the MAC address
                    subprocess.run(
                        ["ip", "link", "set", "dev", interface_name, "address", new_mac],
                        check=True
                    )
                    
                    # Bring the interface back up
                    subprocess.run(
                        ["ip", "link", "set", "dev", interface_name, "up"],
                        check=True
                    )
                    
                elif system == "Darwin":  # macOS
                    # macOS uses ifconfig
                    # First, bring the interface down
                    subprocess.run(
                        ["ifconfig", interface_name, "down"],
                        check=True
                    )
                    
                    # Change the MAC address
                    subprocess.run(
                        ["ifconfig", interface_name, "ether", new_mac],
                        check=True
                    )
                    
                    # Bring the interface back up
                    subprocess.run(
                        ["ifconfig", interface_name, "up"],
                        check=True
                    )
                    
                # Wait a moment for the change to take effect
                time.sleep(2)
                
            # Verify the change
            interfaces = self.get_interfaces()
            for interface in interfaces:
                if interface["name"] == interface_name:
                    if interface["mac"].lower() == new_mac.lower():
                        self.console.print(f"[bold green]MAC address successfully changed to: {new_mac}[/bold green]")
                        return True
                    else:
                        self.console.print(f"[bold yellow]Warning: MAC address change attempted but verification failed.[/bold yellow]")
                        self.console.print(f"Current MAC: {interface['mac']}")
                        return False
                        
            self.console.print(f"[bold red]Error: Interface {interface_name} not found after MAC change.[/bold red]")
            return False
            
        except Exception as e:
            self.console.print(f"[bold red]Error changing MAC address: {str(e)}[/bold red]")
            
            # Provide more specific guidance based on the error
            if "access denied" in str(e).lower() or "permission" in str(e).lower():
                self.console.print("[bold yellow]This operation requires administrator/root privileges.[/bold yellow]")
                if system == "Windows":
                    self.console.print("Please run the program as Administrator.")
                else:
                    self.console.print("Please run the program with sudo.")
                    
            return False
    
    def restore_original_mac(self, interface_name: str) -> bool:
        """
        Restore the original MAC address of a network interface.
        
        Args:
            interface_name: Name of the interface to restore
            
        Returns:
            True if successful, False otherwise
        """
        if interface_name not in self.original_macs:
            self.console.print(f"[bold yellow]No original MAC address stored for {interface_name}.[/bold yellow]")
            return False
            
        original_mac = self.original_macs[interface_name]
        result = self.change_mac(interface_name, original_mac)
        
        if result:
            self.console.print(f"[bold green]Original MAC address restored: {original_mac}[/bold green]")
            # Remove from the original MACs dictionary
            del self.original_macs[interface_name]
            
        return result
    
    def _generate_random_mac(self) -> str:
        """
        Generate a random MAC address.
        
        Returns:
            Random MAC address string
        """
        # Generate random bytes for the MAC address
        mac_bytes = [random.randint(0, 255) for _ in range(6)]
        
        # Ensure it's a unicast, locally administered address
        # Set the second least significant bit of the first byte to 1
        mac_bytes[0] = (mac_bytes[0] & 0xfc) | 0x02
        
        # Format as a MAC address string
        return ':'.join(f"{b:02x}" for b in mac_bytes)
    
    def _validate_mac(self, mac: str) -> bool:
        """
        Validate MAC address format.
        
        Args:
            mac: MAC address to validate
            
        Returns:
            True if valid, False otherwise
        """
        # Check if it matches the format XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(pattern, mac))
