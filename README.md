# Advanced Network Scanner with Nmap

This script provides an advanced network scanning functionality using Nmap (Network Mapper) tool with various options to perform targeted scans on specified IP addresses or websites.

## Features

- **Targeted Scans:** Choose from several scan options:
  - Normal Scan
  - Advanced Scan
  - UDP Scan
  - Cross-Site Request Forgery (CSRF) Scan
  - RTSP Finder
  - Vulnerability (Vuln) Finder
  - Advanced Aggressive Scan

- **Enhanced Scan Parameters:** Each scan option uses specific Nmap arguments tailored for the selected scan type.

- **Detailed Results:** Display information about open ports, services, and additional details:
  - For port 8443 and service 'http': Detects and displays CSRF vulnerabilities.
  - Vulnerability information is shown if 'vulners' script output is available.

## Usage

1. **Requirements:**
   - Python 3.x
   - Nmap installed and accessible from the command line.

2. **Installation:**
   - Clone this repository:
     ```bash
     git clone https://github.com/your-username/advanced-network-scanner.git
     cd advanced-network-scanner
     ```

3. **Usage:**
   - Run the script:
     ```bash
     python advanced_scanner.py
     ```

4. **Instructions:**
   - Input the target IP address or website.
   - Choose a scan option by entering the corresponding number.

5. **Note:**
   - Ensure proper permissions to execute the script.
   - Some scans might require elevated privileges (e.g., root/administrator).

## Example

```bash
$ python advanced_scanner.py
Enter the target IP address or website: 192.168.1.1
Select scan option:
1. Normal scan - Option 1
2. Advanced scan - Option 2
3. UDP scan
4. Cross-Site Request Forgery (CSRF) scan
5. RTSP finder
6. Vuln finder
7. Advanced aggressive scan
Enter your choice (1, 2, 3, 4, 5, 6, 7): 2
# Output showing detailed scan results...
