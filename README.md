# PCAP Network Analysis Tool

A Python based network analysis tool developed as a university coursework project (year 2). The application analyses authorised classic `.pcap` packet-capture files and extracts selected network and HTTP artefacts.

> **Academic project:** This tool is intended for controlled learning environments and packet captures you are authorised to analyse. It should not be used to inspect network traffic without permission.

## Features

* Reads classic PCAP capture files
* Extracts packet metadata, including capture time and frame length
* Identifies IP addresses and MAC addresses from packet data
* Searches HTTP traffic for hostnames and selected `.top` domains
* Compares discovered domains against a supplied domain list
* Extracts search engine referrer information and search queries where available
* Extracts selected cookie values from readable HTTP traffic
* Uses a file selection interface to choose a PCAP file for analysis

## Technologies Used

* Python 3
* Tkinter
* Regular Expressions
* Binary File Handling
* PCAP File Analysis

## Project Structure

```text
pcap-network-analysis-tool/
├── pcap_analyzer.py
├── SearchEngines.txt
├── README.md
└── .gitignore
```

## Getting Started

### Prerequisites

* Python 3
* A classic `.pcap` file that you are authorised to analyse
* Optional: `top-1m.csv` placed in the project directory for the domain-comparison feature

### Run the Application

```bash
python pcap_analyzer.py
```

A file selection window will open. Select an authorised `.pcap` file to begin analysis.

## Notes and Limitations

* This project supports classic `.pcap` files and may not support PCAPNG captures.
* Some features depend on readable HTTP traffic.
* Modern HTTPS traffic is encrypted, so HTTP headers, cookies, referrers and search queries may not be visible.
* The project was created as a learning implementation and is not intended as a production grade forensic or packet analysis platform.
* Packet capture files and generated output are excluded from this repository because they may contain sensitive data.

## What I Learned

* Reading and interpreting binary PCAP file structures
* Extracting network artefacts from packet data
* Using regular expressions to identify HTTP related information
* Working with files selected by users
* Understanding privacy and security considerations when handling network traffic

## Author

Karanveer Singh Malhi
[LinkedIn](https://www.linkedin.com/in/karanveer-singh-malhi-750793311/)
