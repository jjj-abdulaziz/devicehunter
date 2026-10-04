from setuptools import setup, find_packages

setup(
    name="devicehunter",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "python-nmap>=0.7.1",
        "bleak>=0.21.1",
        "requests>=2.31.0",
        "rich>=13.7.0",
    ],
    entry_points={
        "console_scripts": [
            "devicehunter=devicehunter.cli:main",
        ],
    },
    python_requires=">=3.9",
)
