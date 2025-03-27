# NetworkScan Pro

A feature-rich, visually appealing command-line network diagnostic tool with interactive menus, progress visualization, and comprehensive scanning capabilities.

![NetworkScan Pro Banner](https://via.placeholder.com/800x200/0073e6/ffffff?text=NetworkScan+Pro)

## Features

- **Port Scanner**: Scan single IPs or ranges with service detection and response time measurement
- **Ping Utility**: Standard ping with statistics and continuous ping mode
- **Traceroute**: Visual path mapping with latency per hop
- **DNS Tools**: A, MX, TXT, NS record lookup, reverse DNS, and DNS server testing
- **Network Info**: Local IP configuration, public IP detection, and interface statistics
- **Device Discovery**: Scan your local network to find all connected devices with IP/MAC addresses, hostnames, and vendor identification

## Screenshots

Here are some example screenshots of NetworkScan Pro in action:

![Port Scanner](https://via.placeholder.com/400x300/222222/00ff00?text=Port+Scanner)
![Ping Utility](https://via.placeholder.com/400x300/222222/ffff00?text=Ping+Utility)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/networkscanner.git
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

### Command Line Arguments

NetworkScan Pro also supports direct command line usage:

#### Port Scanner

```
python networkscanner.py scan example.com --ports 80,443
python networkscanner.py scan 192.168.1.1 --common
```

#### Ping Utility

```
python networkscanner.py ping example.com --count 10
python networkscanner.py ping 192.168.1.1 --continuous
```

#### Traceroute

```
python networkscanner.py trace example.com --max-hops 20
```

#### DNS Tools

```
python networkscanner.py dns example.com --type a
python networkscanner.py dns example.com --type mx
python networkscanner.py dns 8.8.8.8 --type reverse
```

#### Network Info

```
python networkscanner.py netinfo --type local
python networkscanner.py netinfo --type public
python networkscanner.py netinfo --type stats
```

#### Device Discovery

```
python networkscanner.py discover --network 192.168.1.0/24
python networkscanner.py discover --interface "Ethernet"
python networkscanner.py discover --ping --no-resolve
```

## Technical Details

NetworkScan Pro is built using:

- **Python 3.8+**: Modern, clean, type-hinted code
- **Rich**: For beautiful terminal output with colors and formatting
- **Pythonping**: For accurate latency measurements
- **Scapy**: For advanced packet crafting capabilities
- **DNSPython**: For comprehensive DNS operations

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
