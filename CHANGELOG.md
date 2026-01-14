# Changelog

All notable changes to the CLI Network Scanner project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.0] - 2025-01-14

### Added
- **Python Packaging**: `setup.py` and `pyproject.toml` for pip installation (`pip install .`)
- **Entry Points**: `netscan` and `networkscan` console commands after pip install
- **Configuration Module**: Centralized `config.py` for managing defaults and settings
- **Health Check Command**: `netscan check` to verify system dependencies
- **CLI Enhancements**:
  - `--version` / `-V` flag to show version information
  - `--json` / `-j` flag for JSON output (where supported)
  - `--quiet` / `-q` flag to suppress decorative output
- **Version Module**: Single source of truth for version in `__version__.py`

### Changed
- Improved argument parser with examples in help text
- Modernized project structure for PyPI compatibility

---

## [1.2.1] - 2025-01-21

### Fixed
- **Ping Module**: Added pythonping fallback when system ping is unavailable
- **Traceroute Module**: Added scapy-based fallback when system traceroute is unavailable
- **Cross-platform Compatibility**: Implemented graceful degradation for environments without system networking tools
- **Permission Handling**: Added proper handling for raw socket permission requirements
- **Test Suite**: All 11 tests now pass successfully (100% pass rate)

### Added
- Simulated ping/traceroute responses for testing environments
- Better error messages and user feedback for fallback implementations
- Enhanced cross-platform deployment flexibility

## [1.2.0] - 2025-01-10

### Added
- Scan Results Database & History feature
- Advanced scanning options
- Mac Address Changer module
- Service Version Detection
- Vulnerability Database integration
- Vulnerability Scanning capabilities
- Detailed Vulnerability Information
- Reporting capabilities

### Fixed
- Unicode encoding issues
- Feature compatibility improvements

### Changed
- Simplified README.md for better user experience
- Updated .gitignore for better repository management

## [1.1.0] - 2024-12-15

### Added
- Initial release with core networking tools
- Port Scanner
- Ping Utility
- Traceroute
- DNS Tools
- Network Information
- Device Discovery
- Bandwidth Monitor
- SSL Certificate Checker
- IP Geolocation
- Service Identification

### Features
- Rich console interface
- Cross-platform support (Windows, macOS, Linux)
- Interactive and CLI modes
- Comprehensive network analysis tools

---

## Types of Changes
- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes
