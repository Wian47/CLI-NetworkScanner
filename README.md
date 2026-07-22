<p align="center">
  <img src="https://github.com/user-attachments/assets/9438a168-d813-4c15-8558-897af4c056ef" alt="NetworkScan Pro" width="600">
</p>

<h1 align="center">🌐 NetworkScan Pro</h1>

<p align="center">
  <strong>A powerful command-line network diagnostic toolkit</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/version-1.3.0-orange.svg" alt="Version">
</p>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Port Scanner** | TCP connect, SYN stealth, and advanced scan modes |
| 📶 **Ping Utility** | Test connectivity with detailed statistics |
| 🌐 **Traceroute** | Map the network path to any destination |
| 🔖 **DNS Tools** | Lookup A, MX, TXT, NS records and more |
| 📊 **Network Info** | View local interfaces and public IP details |
| 🔎 **Device Discovery** | Find all devices on your local network |
| 📈 **Bandwidth Monitor** | Real-time upload/download tracking |
| 🔒 **SSL Checker** | Verify certificates, expiry dates, and chain |
| 🌍 **IP Geolocation** | Map IPs to physical locations with interactive maps |
| 🛡️ **Vulnerability Scanner** | Detect known service vulnerabilities |
| 📱 **MAC Changer** | Change network interface MAC addresses |

---

## 🚀 Installation

### Quick Install (Recommended)

```bash
git clone https://github.com/Wian47/CLI-NetworkScanner.git
cd CLI-NetworkScanner
pip install -e .
```

Now use `netscan` from anywhere:

```bash
netscan --version
netscan check        # Verify system dependencies
netscan --help       # See all commands
```

### Manual Run

```bash
git clone https://github.com/Wian47/CLI-NetworkScanner.git
cd CLI-NetworkScanner
pip install -r requirements.txt
python networkscanner.py
```

---

## 📖 Usage

### Port Scanning

```bash
# Scan specific ports
netscan scan google.com --ports 80,443,8080

# Scan common ports
netscan scan 192.168.1.1 --common

# Scan a range
netscan scan target.com --ports 20-100
```

### Network Diagnostics

```bash
# Ping with custom count
netscan ping google.com --count 10

# Trace route to destination
netscan trace cloudflare.com --max-hops 20

# DNS lookups
netscan dns example.com --type mx
netscan dns example.com --type txt
```

### Network Discovery

```bash
# Find devices on your network
netscan discover

# Get local network info
netscan netinfo --type local

# Get public IP info
netscan netinfo --type public
```

### Security Tools

```bash
# Check SSL certificate
netscan ssl github.com

# IP geolocation
netscan geoip 8.8.8.8

# Geolocation with interactive map
netscan geoip 1.1.1.1 --output map.html --open
```

### Output Options

```bash
# JSON output for scripting
netscan --json check
netscan --json ping google.com --count 2

# Quiet mode (no banner)
netscan --quiet ping google.com
```

---

## 🛠️ For Developers

<details>
<summary><strong>Repository Management Tools</strong></summary>

```bash
# Interactive dashboard
python scripts/repo_dashboard.py

# Health check
python scripts/repo_health_check.py

# Version management
python scripts/version_manager.py
```

</details>

<details>
<summary><strong>Automated CI/CD</strong></summary>

- **GitHub Actions** - Multi-platform testing (Windows, macOS, Linux)
- **Dependabot** - Automated dependency updates
- **Security Scanning** - Bandit and safety audits
- **Code Quality** - Automated linting and formatting

</details>

---

## 📋 Requirements

- **Python** 3.10 or higher
- **Platform**: Windows, macOS, or Linux
- **Optional**: Admin/root privileges for advanced scanning features

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Made with ❤️ for network administrators and security enthusiasts
</p>
