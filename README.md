# sp_scanner
Sharepoint scanner

Scans Sharepoint instances for the following vulnerabilities:
* Anonymous access [[1]](https://www.owasp.org/index.php/Broken_Access_Control)
* IIS tilde enumeration [[2]](https://www.acunetix.com/vulnerabilities/web/microsoft-iis-tilde-directory-enumeration/)
* Information disclosure via HTTP response headers [[3]](https://www.owasp.org/index.php/Top_10-2017_A3-Sensitive_Data_Exposure)
* Missing security headers [[4]](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#tab=Headers)

# Usage

```sp_scan.py [-u <URL>] [-f <FILE>] [-v true]```

Options:

* -u, --url - Sharepoint instance URL
* -f, --file - Name of a file with a list of URLs
* -v - display verbose information (default value: false)
