#!/usr/bin/env python3
"""Setup script for CLI Network Scanner."""

from setuptools import setup, find_packages
from pathlib import Path

# Read version from __version__.py
version = {}
with open("__version__.py") as f:
    exec(f.read(), version)

# Read README for long description
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements = []
req_path = Path(__file__).parent / "requirements.txt"
if req_path.exists():
    requirements = [
        line.strip() 
        for line in req_path.read_text().splitlines() 
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="networkscan-pro",
    version=version["__version__"],
    author=version.get("__author__", ""),
    description=version.get("__description__", "Advanced CLI Network Diagnostics Tool"),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Wian47/CLI-NetworkScanner",
    license="MIT",
    packages=find_packages(),
    py_modules=[
        "networkscanner",
        "database",
        "history",
        "reporting",
        "config",
        "__version__",
    ],
    include_package_data=True,
    package_data={
        "": ["*.txt", "*.md"],
        "modules": ["data/*"],
    },
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.2.5",
            "black",
            "flake8",
        ],
    },
    entry_points={
        "console_scripts": [
            "netscan=networkscanner:main",
            "networkscan=networkscanner:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Utilities",
    ],
    keywords="network scanner ping traceroute dns ssl security cli",
)
