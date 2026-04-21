# Roger Redirect 🐰

Open redirect vulnerability scanner for bug bounty hunting. Tests for URL redirection vulnerabilities.

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

## License

MIT License