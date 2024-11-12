# sp_scanner - SharePoint Vulnerability Scanner

sp_scanner is a tool that scans SharePoint instances for common security vulnerabilities, including access control flaws, information disclosure, and missing security headers.

# Scanned Vulnerabilities

Scans SharePoint instances for the following vulnerabilities:

* **Anonymous Access** [[1]](https://www.owasp.org/index.php/Broken_Access_Control): Checks for resources accessible without authentication.
* **IIS Tilde Enumeration** [[2]](https://www.acunetix.com/vulnerabilities/web/microsoft-iis-tilde-directory-enumeration/): Tests for the ability to enumerate file names in IIS using tilde-based requests.
* **Information Disclosure via HTTP Response Headers** [[3]](https://www.owasp.org/index.php/Top_10-2017_A3-Sensitive_Data_Exposure): Identifies headers that could disclose sensitive information.
* **Missing Security Headers** [[4]](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#tab=Headers): Scans for missing HTTP headers that protect against various attacks.

# Prerequisites

- **Python 3.6+**: Make sure Python 3.6 or newer is installed.

# Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/sp_scanner.git
    ```
2. Navigate to the directory:
    ```sh
    cd sp_scanner
    ```
3. Install ```requests```:
    ```sh
    pip install requests
    ```

# Usage

To run sp_scanner, use the following command:

```sh
python sp_scan.py [-u <URL>] [-f <FILE>] [-v true]
-u, --url - Target SharePoint instance URL.
-f, --file - Path to a file containing a list of URLs (one per line).
-v, --verbose - Display verbose information (default: false).
```
# Examples
Scan a Single URL:

```python sp_scan.py -u https://example.com```

Scan Multiple URLs from a File:

```python sp_scan.py -f urls.txt -v true```

# Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, feel free to open an issue or submit a pull request.

# Disclaimer
This tool is intended for educational purposes only. Use it responsibly and only on systems you have permission to test.

Feel free to copy and paste this into your README file directly! Let me know if there's any
