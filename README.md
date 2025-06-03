# SSL Stripping Detection Tool

A Python-based GUI tool to detect SSL stripping attacks in PCAP files. This project was developed as a practical implementation to demonstrate how SSL stripping attacks can be detected using packet analysis.

**Disclaimer:** This project was originally developed in 2023 and has not been actively maintained since. It may not reflect current best practices or be compatible with the latest libraries and environments. Use it primarily for educational and research purposes.

## Features
- Analyze `.pcap` files using PyShark
- Detect SSL stripping indicators:
  - HTTP responses instead of HTTPS
  - Missing `upgrade-insecure-requests` header
  - HTML links downgraded to HTTP
- Export network connection logs to CSV
- User-friendly GUI built with Tkinter

## Getting Started

### Prerequisites
Make sure Python 3.x is installed.

### Install Dependencies
```
pip install -r requirements.txt
```

### Run the Tool
```
python ssl_stripping_tool.py
```

### Sample PCAP
A test PCAP file is available under `/test_files` to validate tool functionality.

## GUI Preview
Add a screenshot named `gui_screenshot.png` here.

## Methodology
The tool parses HTTP traffic using PyShark and applies logic to:
- Identify HTTP responses with 200 OK
- Check for missing HTTPS upgrade directives
- Analyze embedded links in HTML for insecure references

## Future Enhancements
- Add deeper TLS/SSL handshake inspection
- Add CLI support for headless use
- Implement alert signatures for specific attack types

## Directory Structure
```
ssl-stripping-detector/
├── README.md
├── LICENSE
├── requirements.txt
├── ssl_stripping_tool.py
├── gui_screenshot.png
├── test_files/
│   └── sample.pcap
└── docs/
    ├── architecture.png
    └── user_manual.pdf
```

## License
MIT License

## Acknowledgements
- Python Community & Open Source Contributors
- Wireshark & PyShark developers
