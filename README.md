# sp_scanner
Sharepoint scanner

Scans Sharepoint instances for the following vulnerabilities:
* Anonymous access
* IIS tilde enumeration
* Information disclosure via HTTP response headers
* Missing security headers

# Usage

sp_scan.py [-u <URL>] [-f <FILE>] [-v true]

Options:

* -u, --url - Sharepoint instance URL
* -f, --file - Name of a file with a list of URLs
* -v - display verbose information (default value: false)
