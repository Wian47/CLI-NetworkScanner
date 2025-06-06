# CLI Network Scanner

A simple command-line network diagnostic tool for scanning ports, checking connectivity, and gathering network information.

![image](https://github.com/user-attachments/assets/9438a168-d813-4c15-8558-897af4c056ef)

## Features

- **Port Scanner** - Scan ports on target hosts
- **Ping** - Test connectivity to hosts
- **Traceroute** - Trace network path to destination
- **DNS Tools** - Lookup DNS records (A, MX, TXT, etc.)
- **Network Info** - Show local and public IP information
- **Device Discovery** - Find devices on your network
- **SSL Checker** - Verify SSL certificates
- **IP Geolocation** - Get location info for IP addresses

## Quick Start

1. **Install Python 3.8+**

2. **Clone and install:**
   ```bash
   git clone https://github.com/Wian47/CLI-NetworkScanner.git
   cd CLI-NetworkScanner
   pip install -r requirements.txt
   ```

3. **Run:**
   ```bash
   python networkscanner.py
   ```

## Usage Examples

**Port Scanning:**
```bash
python networkscanner.py scan google.com --ports 80,443
python networkscanner.py scan 192.168.1.1 --common
```

**Ping:**
```bash
python networkscanner.py ping google.com --count 5
```

**DNS Lookup:**
```bash
python networkscanner.py dns google.com --type a
python networkscanner.py dns google.com --type mx
```

**Network Info:**
```bash
python networkscanner.py netinfo --type local
python networkscanner.py netinfo --type public
```

**SSL Check:**
```bash
python networkscanner.py ssl google.com
```

**IP Location:**
```bash
python networkscanner.py geoip 8.8.8.8
```

**Find Devices:**
```bash
python networkscanner.py discover
```

## Help

Get help for any command:
```bash
python networkscanner.py --help
python networkscanner.py scan --help
```

## Requirements

- Python 3.8+
- Windows, macOS, or Linux
- Admin privileges for some features (optional)

## License

MIT License - see LICENSE file for details.
