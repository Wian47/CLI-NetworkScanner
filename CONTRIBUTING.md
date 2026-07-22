# Contributing to CLI Network Scanner

Thank you for your interest in contributing to the CLI Network Scanner! This document provides guidelines and information for contributors.

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- Git
- Basic understanding of networking concepts

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR_USERNAME/CLI-NetworkScanner.git
   cd CLI-NetworkScanner
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run Tests**
   ```bash
   python test_all_features.py
   ```

## 📝 How to Contribute

### Reporting Bugs
- Use the GitHub Issues tab
- Include detailed description and steps to reproduce
- Specify your operating system and Python version
- Include error messages and logs if applicable

### Suggesting Features
- Open an issue with the "enhancement" label
- Describe the feature and its use case
- Explain why it would be valuable to users

### Code Contributions

#### Branch Naming
- `feature/description` - for new features
- `fix/description` - for bug fixes
- `docs/description` - for documentation updates

#### Coding Standards
- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Include type hints where appropriate

#### Example Function Structure
```python
def scan_port(self, ip: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Scan a single port on the target IP.
    
    Args:
        ip: Target IP address
        port: Port number to scan
        timeout: Connection timeout in seconds
        
    Returns:
        Dictionary containing scan results
    """
    # Implementation here
```

### Testing
- All new features must include tests
- Ensure all existing tests pass
- Test on multiple platforms if possible
- Use the provided `test_all_features.py` for comprehensive testing

### Pull Request Process

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Write clean, documented code
   - Add tests for new functionality
   - Update documentation if needed

3. **Test Thoroughly**
   ```bash
   python test_all_features.py
   ```

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "Add feature: description of changes"
   ```

5. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```
   Then create a Pull Request on GitHub

#### PR Requirements
- Clear description of changes
- Reference any related issues
- Include test results
- Update CHANGELOG.md if applicable

## 🏗️ Project Structure

```
CLI-NetworkScanner/
├── modules/                 # Core functionality modules
│   ├── ping_utility.py     # Ping implementation
│   ├── port_scanner.py     # Port scanning
│   ├── traceroute.py       # Traceroute implementation
│   └── ...                 # Other modules
├── data/                   # Database and data files
├── reports/                # Generated reports
├── networkscanner.py       # Main application
├── test_all_features.py    # Comprehensive test suite
├── requirements.txt        # Dependencies
└── README.md              # Project documentation
```

## 🔧 Module Development Guidelines

### Adding New Modules
1. Create module in `modules/` directory
2. Follow existing module patterns
3. Include comprehensive error handling
4. Add fallback implementations when possible
5. Update main application to integrate module

### Error Handling
- Use try-catch blocks appropriately
- Provide meaningful error messages
- Implement graceful degradation
- Log errors for debugging

## 📚 Documentation

- Update README.md for user-facing changes
- Add docstrings to all new functions
- Update CHANGELOG.md for all changes
- Include examples in documentation

## 🤝 Community Guidelines

- Be respectful and inclusive
- Help others learn and grow
- Provide constructive feedback
- Follow the code of conduct

## 📞 Getting Help

- Open an issue for questions
- Check existing issues and documentation first
- Be specific about your problem or question

## 🏷️ Release Process

1. Update version numbers
2. Update CHANGELOG.md
3. Create release tag
4. Update documentation

Thank you for contributing to make CLI Network Scanner better! 🎉
