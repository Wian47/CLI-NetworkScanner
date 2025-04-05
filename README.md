# NetworkScan Pro

A feature-rich, visually appealing command-line network diagnostic tool with interactive menus, progress visualization, and comprehensive scanning capabilities.

![image](https://github.com/user-attachments/assets/9438a168-d813-4c15-8558-897af4c056ef)


## Features

- **Port Scanner**: Scan single IPs or ranges with service detection and response time measurement
- **Ping Utility**: Standard ping with statistics and continuous ping mode with real-time visualization
- **Traceroute**: Visual path mapping with latency per hop and network geography information
- **DNS Tools**: A, MX, TXT, NS record lookup, reverse DNS, and DNS server testing
- **Network Info**: Local IP configuration, public IP detection, and interface statistics
- **Device Discovery**: Scan your local network to find all connected devices with IP/MAC addresses, hostnames, and vendor identification
- **Bandwidth Monitor**: Track and visualize real-time network usage with graphs showing upload/download speeds
- **SSL Certificate Checker**: Verify website certificates, check expiration dates, and validate certificate chains
- **IP Geolocation**: Map IP addresses to physical locations with interactive HTML maps and visualize network paths across the globe
- **Scan History**: Store, view, and compare scan results over time with a comprehensive history database
- **Export Reports**: Generate professional reports in HTML, CSV, and JSON formats for sharing and analysis
-
## Requirements

- **Python 3.8+** or newer
- Administrative/root privileges for some advanced features (SYN scanning, ARP device discovery)
- Network connectivity
- Supported platforms: Windows, macOS, Linux

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/Wian47/networkscanner.git
   cd networkscanner
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Interactive Mode

Run the tool without arguments to enter the interactive menu:

```
python networkscanner.py
```

The interactive menu provides a user-friendly interface with detailed options and help text for each feature.

### Command Line Arguments

NetworkScan Pro also supports direct command line usage:

#### Port Scanner

```
python networkscanner.py scan example.com --ports 80,443
python networkscanner.py scan 192.168.1.1 --common
python networkscanner.py scan 8.8.8.8 --ports 1-1000 --threads 50
```

#### Ping Utility

```
python networkscanner.py ping example.com --count 10
python networkscanner.py ping 192.168.1.1 --continuous
python networkscanner.py ping google.com --count 20
```

#### Traceroute

```
python networkscanner.py trace example.com --max-hops 20
python networkscanner.py trace 8.8.8.8 --max-hops 15
```

#### DNS Tools

```
python networkscanner.py dns example.com --type a
python networkscanner.py dns example.com --type mx
python networkscanner.py dns 8.8.8.8 --type reverse
python networkscanner.py dns gmail.com --type txt
python networkscanner.py dns example.com --type test --server 1.1.1.1
```

#### Network Info

```
python networkscanner.py netinfo --type local
python networkscanner.py netinfo --type public
python networkscanner.py netinfo --type stats
```

#### Device Discovery

```
python networkscanner.py discover                            # Auto-detect network and scan
python networkscanner.py discover --network 192.168.1.0/24   # Scan specific network
python networkscanner.py discover --interface "Ethernet"     # Scan specific interface
python networkscanner.py discover --ping --no-resolve        # Use ping instead of ARP, skip hostname resolution
python networkscanner.py discover --threads 100              # Use more threads for faster scanning
```

#### Bandwidth Monitor

```
python networkscanner.py bandwidth                           # Monitor all interfaces until stopped
python networkscanner.py bandwidth --interface "Wi-Fi"       # Monitor specific interface
python networkscanner.py bandwidth --duration 300            # Monitor for 5 minutes
python networkscanner.py bandwidth --interval 0.5            # More frequent updates (twice per second)
```

#### SSL Certificate Checker

```
python networkscanner.py ssl example.com                     # Check certificate for example.com
python networkscanner.py ssl secure.site.com --port 8443     # Check certificate on non-standard port
python networkscanner.py ssl example.com --save report.txt   # Save results to file
python networkscanner.py ssl --batch sites.txt --threads 5   # Batch check certificates for sites in file
```

#### IP Geolocation

```
python networkscanner.py geoip 8.8.8.8                       # Look up geolocation for an IP address
python networkscanner.py geoip google.com                    # Look up geolocation for a hostname
python networkscanner.py geoip 1.1.1.1 --trace               # Trace network path with geolocation
python networkscanner.py geoip example.com --output map.html # Generate interactive HTML map
python networkscanner.py geoip 8.8.8.8 --output map.html --open # Generate and open map in browser
```

## Advanced Usage

### Port Scanning Options

- **Regular vs. Advanced Scanning**: The tool will automatically use SYN scanning when run with admin privileges for better stealth and accuracy
- **Thread Customization**: Adjust thread count to balance speed vs. system resource usage

### Device Discovery Options

- **ARP vs. Ping**: ARP scanning is faster and provides MAC addresses but requires admin privileges, while ping works on any system
- **Hostname Resolution**: Enable/disable hostname lookups depending on speed requirements
- **Network Range**: Automatically detects your network or allows custom CIDR notation networks

### Bandwidth Monitoring Options

- **Interface Selection**: Monitor all network interfaces or choose a specific one
- **Real-time Visualization**: See bandwidth usage as it happens with ASCII graphs
- **Duration Control**: Monitor for a specific time period or run continuously
- **History Tracking**: View trends over the last minute of network activity
- **Custom Intervals**: Adjust update frequency to balance between detail and system resource usage

### SSL Certificate Checking Options

- **Hostname Validation**: Verify that certificates match the requested hostname, including wildcard support
- **Expiration Checking**: Identify certificates that are expired or expiring soon
- **Chain Validation**: Confirm that certificates have a proper trust chain
- **Security Assessment**: Detect weak algorithms, small key sizes, and outdated protocols
- **Batch Processing**: Check multiple certificates in parallel with customizable thread count

### IP Geolocation Options

- **Single IP Lookup**: Look up details about any IP address or hostname
- **Path Tracing**: Visualize the network path to a target with geolocation data for each hop
- **Interactive Maps**: Generate interactive HTML maps with detailed location information
- **Browser Integration**: Automatically open generated maps in your default web browser
- **Caching System**: Local caching of IP lookup results to reduce API calls and improve performance

### Scan History and Reporting Options

- **Persistent Storage**: Save scan results to a SQLite database for future reference
- **Historical Analysis**: View past scans with detailed information about results
- **Comparison Tool**: Compare two scans to identify changes in network configuration
- **Multiple Export Formats**: Generate reports in HTML, CSV, and JSON formats
- **Custom Filenames**: Specify custom filenames for exported reports
- **Professional HTML Reports**: Create visually appealing HTML reports with tables and styling

## Troubleshooting

- **Permission Issues**: Some features require administrative/root privileges. Run as admin/sudo for full functionality.
- **Missing MAC Addresses**: If device discovery isn't showing MAC addresses, try running with admin privileges or switching to ARP mode.
- **Port Scan Accuracy**: If port scan results show many "filtered" ports, try increasing timeout values or using advanced scanning.
- **Network Range Detection**: If automatic network detection fails, specify your network manually using CIDR notation.
- **SSL Certificate Issues**: If certificate validation fails, check for clock synchronization issues or network restrictions.
- **Geolocation API Limits**: The IP geolocation feature uses a free API with rate limiting. If you encounter errors, wait a few minutes before trying again.

## Technical Details

NetworkScan Pro is built using:

- **Python 3.8+**: Modern, clean, type-hinted code
- **Rich**: For beautiful terminal output with colors and formatting
- **Pythonping**: For accurate latency measurements
- **Scapy**: For advanced packet crafting capabilities
- **DNSPython**: For comprehensive DNS operations
- **Folium**: For generating interactive maps of IP locations and network paths
