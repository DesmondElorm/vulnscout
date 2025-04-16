 Installation & Setup Guide

 System Requirements

- Operating System: Linux (Ubuntu 20.04+ recommended), macOS 10.15+, or Windows 10/11 with WSL
- Python: Version 3.8 or higher
- RAM: Minimum 4GB (8GB+ recommended for large scans)
- Storage: 500MB for application, additional space for scan results
- Network: Unrestricted outbound access for scanning

 Dependencies

 Core Dependencies
- Python 3.8+
- Nmap 7.80+ (with scripts)
- Redis Server (optional for caching)
- Elasticsearch 7.x+ (optional for result storage)
- wkhtmltopdf (for PDF report generation)

System Package Dependencies

Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-dev nmap redis-server wkhtmltopdf libssl-dev libffi-dev build-essential
