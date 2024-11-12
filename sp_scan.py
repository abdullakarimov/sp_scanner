import argparse
import requests
import logging
from concurrent.futures import ThreadPoolExecutor
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Creating a session and setting a custom User-Agent
s = requests.Session()
s.headers.update({
    'User-Agent': 'sp_scanner/1.0 (https://github.com/yourusername/sp_scanner)'
})

# Reading fuzz lines from file
with open("fuzz.txt") as f:
    fuzz_lines = [x.strip() for x in f.readlines()]

def anon_access(target, verbose=False):
    accessible_paths = []
    for fuzz_line in fuzz_lines:
        try:
            r = s.get(target + fuzz_line, allow_redirects=True, timeout=10)
            if r.status_code == 200 and "SharePointError" not in r.text:
                accessible_paths.append(fuzz_line)
            # Rate limiting: add delay to avoid overwhelming the server
            time.sleep(0.5)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error requesting {target + fuzz_line}: {str(e)}")
    
    if accessible_paths:
        logging.info(f"{target} is vulnerable to Anonymously Accessible Resources.")
        if verbose:
            logging.info("The following resources are available for anonymous access:")
            for path in accessible_paths:
                logging.info(path)

def iis_tilde(target, verbose=False):
    verbs = ["DEBUG", "TRACE", "OPTIONS", "GET", "HEAD"]

    for verb in verbs:
        try:
            r1 = s.request(verb, target + "/a*~1*", timeout=10)
            r2 = s.request(verb, target + "/aa*~1*", timeout=10)
            if r1.status_code != r2.status_code or r1.text != r2.text:
                logging.info(f"{target} is vulnerable to IIS Tilde Enumeration. Used HTTP method: {verb}")
                if verbose:
                    logging.info("Proof of concept:")
                    logging.info(f"curl -IX {verb} {target}/a*~1*")
                    logging.info(f"curl -IX {verb} {target}/aa*~1*")
                break
            # Rate limiting: add delay to avoid overwhelming the server
            time.sleep(0.5)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error during IIS Tilde Enumeration for {target}: {str(e)}")

def info_disclosure(target, verbose=False):
    info_headers = ["Server", "X-SharePointHealthScore", "SPRequestGuid", "request-id", 
                    "X-Forms_Based_Auth_Required", "X-Forms_Based_Auth_Return_Url", 
                    "X-MSDAVEXT_Error", "X-Powered-By", "MicrosoftSharePointTeamServices", 
                    "X-MS-InvokeApp"]
    try:
        r = s.get(target, timeout=10)
        resp_headers = [header for header in r.headers if header in info_headers]
        if resp_headers:
            logging.info(f"{target} is vulnerable to Information Disclosure in HTTP Response Headers.")
            if verbose:
                logging.info("List of the headers:")
                for resp_header in resp_headers:
                    logging.info(f"{resp_header}: {r.headers[resp_header]}")
                    if resp_header in ["Server", "X-Powered-By"]:
                        logging.info("Explanation: These headers can provide information about the underlying server technology, making it easier for attackers to target specific vulnerabilities.")
                    elif resp_header in ["X-SharePointHealthScore", "MicrosoftSharePointTeamServices"]:
                        logging.info("Explanation: These headers disclose SharePoint-specific information, which can help attackers identify the presence of SharePoint and potentially exploit known vulnerabilities.")
            # Rate limiting: add delay to avoid overwhelming the server
            time.sleep(0.5)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during info disclosure scan for {target}: {str(e)}")

def sec_headers(target, verbose=False):
    s_headers = ["strict-transport-security", "referrer-policy", "x-xss-protection", "content-security-policy"]
    try:
        r = s.get(target, timeout=10)
        resp_headers = [header.lower() for header in r.headers]

        missing_headers = [s_header for s_header in s_headers if s_header not in resp_headers]
        if missing_headers:
            logging.info(f"{target} is vulnerable to Missing Security Headers.")
            if verbose:
                logging.info("Missing headers:")
                for s_header in missing_headers:
                    logging.info(s_header)
                    if s_header == "strict-transport-security":
                        logging.info("Explanation: The Strict-Transport-Security (HSTS) header ensures that browsers only communicate with the server over HTTPS, preventing man-in-the-middle attacks.")
                    elif s_header == "referrer-policy":
                        logging.info("Explanation: The Referrer-Policy header controls how much referrer information is sent, which helps to minimize information leakage.")
                    elif s_header == "x-xss-protection":
                        logging.info("Explanation: The X-XSS-Protection header helps prevent cross-site scripting attacks by instructing the browser to block or sanitize suspicious content.")
                    elif s_header == "content-security-policy":
                        logging.info("Explanation: The Content-Security-Policy (CSP) header helps to prevent a range of attacks, including XSS, by controlling which resources can be loaded on the page.")
            # Rate limiting: add delay to avoid overwhelming the server
            time.sleep(0.5)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during security headers scan for {target}: {str(e)}")

def scan(target_url, is_verbose):
    logging.info('Starting SharePoint scanner. This may take a while.')
    if target_url.endswith('/'):
        target_url = target_url[:-1]
    
    anon_access(target_url, is_verbose)
    iis_tilde(target_url, is_verbose)
    info_disclosure(target_url, is_verbose)
    sec_headers(target_url, is_verbose)

def main():
    parser = argparse.ArgumentParser(description='Scan Sharepoint instances for common vulnerabilities')
    parser.add_argument('-u', '--url', metavar='u', help='target URL')
    parser.add_argument('-f', '--file', metavar='f', help='path to file with URLs')
    parser.add_argument('-v', '--verbose', action='store_true', help='display verbose information')
    args = parser.parse_args()

    if args.url:
        scan(args.url, args.verbose)
    elif args.file:
        with open(args.file) as f:
            urls = [x.strip() for x in f.readlines()]
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in urls:
                if url.startswith("http"):
                    executor.submit(scan, url, args.verbose)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
