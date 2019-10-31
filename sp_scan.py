import argparse
import requests

s = requests.session()

with open("fuzz.txt") as f:
    fuzz_lines = f.readlines()
fuzz_lines = [x.strip() for x in fuzz_lines]


def anon_access(target, verbose=False):
    accessible_paths = []
    for fuzz_line in fuzz_lines:
        r = s.get(target + fuzz_line, allow_redirects=True)

        if r.status_code == 200 and "SharePointError" not in r.text:
            accessible_paths.append(fuzz_line)
    if len(accessible_paths) > 0:
        print(target + " is vulnerable to Anonymously Accessible Resources.")
        if verbose:
            print()
            print("The following resources available for anonymous access:")
            for path in accessible_paths:
                print(path)


def iis_tilde(target, verbose=False):
    verbs = ["DEBUG", "TRACE", "OPTIONS", "GET", "HEAD"]

    for verb in verbs:
        r1 = s.request(verb, target + "/a*~1*")
        r2 = s.request(verb, target + "/aa*~1*")
        if r1 != r2:
            print(target + " is vulnerable to IIS Tilde Enumeration. Used HTTP method: " + verb)
            if verbose:
                print()
                print("Proof of concept: ")
                print("curl -IX" + verb + " " + target + "/a*~1*")
                print("curl -IX" + verb + " " + target + "/aa*~1*")
            break


def info_disclosure(target, verbose=False):
    info_headers = ["Server",
                    "X-SharePointHealthScore",
                    "SPRequestGuid",
                    "request-id",
                    "X-Forms_Based_Auth_Required",
                    "X-Forms_Based_Auth_Return_Url",
                    "X-MSDAVEXT_Error",
                    "X-Powered-By",
                    "MicrosoftSharePointTeamServices",
                    "X-MS-InvokeApp"]
    resp_headers = []
    r = s.get(target + "/")
    for header in r.headers:
        if header in info_headers:
            resp_headers.append(header)
    if len(resp_headers) > 0:
        print(target + " is vulnerable to Information Disclosure in HTTP Response Headers.")
        if verbose:
            print()
            print("List of the headers:")
            for resp_header in resp_headers:
                print(resp_header)


def sec_headers(target, verbose=False):
    s_headers = ["strict-transport-security ",
                 "referrer-policy",
                 "x-xss-protection"
                 ]
    resp_headers = []
    r = s.get(target + "/")
    for header in r.headers:
        resp_headers.append(header.lower())

    for s_header in s_headers:
        if s_header not in resp_headers:
            print(target + " is vulnerable to Missing Security Headers.")
            break

    if verbose:
        print()
        print("Missing headers:")
        for s_header in s_headers:
            if s_header not in resp_headers:
                print(s_header)


def scan(target_url, is_verbose):
    if target_url.endswith('/'):
        target_url = url[:-1]
        try:
            print()
            print('--------------------------------------------------------------')
            print()
            anon_access(target_url, is_verbose)
        except Exception as e:
            print("Error: could not scan " + target_url + ". Exception: " + str(e))
        try:
            print()
            print('--------------------------------------------------------------')
            print()
            iis_tilde(target_url, is_verbose)
        except Exception as e:
            print("Error: could not scan " + target_url + ". Exception: " + str(e))
        try:
            print()
            print('--------------------------------------------------------------')
            print()
            info_disclosure(target_url, is_verbose)
        except Exception as e:
            print("Error: could not scan " + target_url + ". Exception: " + str(e))
        try:
            print()
            print('--------------------------------------------------------------')
            print()
            sec_headers(target_url, is_verbose)
        except Exception as e:
            print("Error: could not scan " + target_url + ". Exception: " + str(e))


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


parser = argparse.ArgumentParser(description='Scan Sharepoint instances for common vulnerabilities')
parser.add_argument('-u', '--url', metavar='u', help='target URL')
parser.add_argument('-f', '--file', metavar='f', help='path to file with URLs')
parser.add_argument('-v', '--verbose', metavar='v', help='display verbose information', type=str2bool, default=False)
args = parser.parse_args()

url = str(args.url)
filename = str(args.file)
verbose = args.verbose

if url:
    if url.endswith('/'):
        url = url[:-1]

if url != "None":
    scan(url, verbose)
else:
    if filename != "None":
        with open(filename) as f:
            urls = f.readlines()
        urls = [x.strip() for x in urls]
        for url in urls:
            if url.startswith("http"):
                scan(url, verbose)
