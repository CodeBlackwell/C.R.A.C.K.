#!/usr/bin/env python3
"""
Setup configuration for C.R.A.C.K. (Comprehensive Recon & Attack Creation Kit)
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file if it exists
this_directory = Path(__file__).parent
long_description = ""
readme_file = this_directory / "README.md"
if readme_file.exists():
    long_description = (this_directory / "README.md").read_text()

setup(
    name="crack-toolkit",
    version="1.0.0",
    author="OSCP Student",
    description="Comprehensive Recon & Attack Creation Kit - Professional pentesting tools for OSCP",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/crack",
    packages=find_packages() + ['crack'],
    package_dir={'crack': '.'},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
        "beautifulsoup4>=4.9.0",
        "urllib3>=1.26.0",
    ],
    entry_points={
        "console_scripts": [
            # Main command with subcommands
            "crack=crack.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)