# Roger Redirect 🐰

[![Python 3.7+](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Open redirect vulnerability scanner for bug bounty hunting.**

Tests for URL redirection vulnerabilities that can be used for phishing, OAuth token theft, and bypassing security controls.

Part of the [Roger Toolkit](https://github.com/jrabbit00/roger-recon) - 14 free security tools for bug bounty hunters.

🔥 **[Get the complete toolkit on Gumroad](https://jrabbit00.gumroad.com)**

## Why Open Redirect?

Open redirects are common bug bounty findings:
- Phishing attack vector
- Bypassing whitelists
- OAuth token theft
- Bypassing CSP

## Features

- Tests 25+ redirect payloads
- Parameter injection testing
- Multiple bypass techniques
- External redirect detection

## Installation

```bash
git clone https://github.com/jrabbit00/roger-redirect.git
cd roger-redirect
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python3 redirect.py https://target.com/login?next=/dashboard

# Save results
python3 redirect.py target.com -o findings.txt
```

## What It Tests

- Standard redirects (//evil.com)
- Protocol-relative (///google.com)
- Parameter injection
- Unicode bypasses
- Data URI redirects
- Path-based redirects

## Common Vulnerable Parameters

- url, redirect, next, callback
- dest, destination, return_to
- link, src, source
- continue, destination_url

## Important Notes

- Always have authorization
- Check bug bounty scope
- Manual verification needed

## 🐰 Part of the Roger Toolkit

| Tool | Purpose |
|------|---------|
| [roger-recon](https://github.com/jrabbit00/roger-recon) | All-in-one recon suite |
| [roger-direnum](https://github.com/jrabbit00/roger-direnum) | Directory enumeration |
| [roger-jsgrab](https://github.com/jrabbit00/roger-jsgrab) | JavaScript analysis |
| [roger-sourcemap](https://github.com/jrabbit00/roger-sourcemap) | Source map extraction |
| [roger-paramfind](https://github.com/jrabbit00/roger-paramfind) | Parameter discovery |
| [roger-wayback](https://github.com/jrabbit00/roger-wayback) | Wayback URL enumeration |
| [roger-cors](https://github.com/jrabbit00/roger-cors) | CORS misconfigurations |
| [roger-jwt](https://github.com/jrabbit00/roger-jwt) | JWT security testing |
| [roger-headers](https://github.com/jrabbit00/roger-headers) | Security header scanner |
| [roger-xss](https://github.com/jrabbit00/roger-xss) | XSS vulnerability scanner |
| [roger-sqli](https://github.com/jrabbit00/roger-sqli) | SQL injection scanner |
| [roger-redirect](https://github.com/jrabbit00/roger-redirect) | Open redirect finder |
| [roger-idor](https://github.com/jrabbit00/roger-idor) | IDOR detection |
| [roger-ssrf](https://github.com/jrabbit00/roger-ssrf) | SSRF vulnerability scanner |

## ☕ Support

If Roger Redirect helps you find vulnerabilities, consider [supporting the project](https://github.com/sponsors/jrabbit00)!

## License

MIT License - Created by [J Rabbit](https://github.com/jrabbit00)