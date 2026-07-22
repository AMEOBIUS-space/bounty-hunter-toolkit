# Building a Recon Pipeline with Python

> A practical guide to automated reconnaissance for bug bounty
> using zero-dependency Python tooling.

## Pipeline Stages

### 1. Subdomain Enumeration

```python
from bounty_hunter_toolkit import SubdomainEnum

enum = SubdomainEnum(
    domain="example.com",
    sources=["crtsh", "hackertarget", "threatcrowd"]
)
subdomains = enum.run()
print(f"Found {len(subdomains)} subdomains")
```

### 2. HTTP Probing

```python
from bounty_hunter_toolkit import HTTPProbe

probe = HTTPProbe(targets=subdomains, timeout=5, threads=20)
live = probe.run()
# Returns: status, title, tech stack, content-length
```

### 3. Vulnerability Scanning

```python
from bounty_hunter_toolkit import VulnScan

scanner = VulnScan(
    targets=live,
    checks=["cors", "open-redirect", "sensitive-files", "headers"]
)
findings = scanner.run()
```

### 4. Evidence Collection

Every finding includes:
- Full request/response pairs
- Screenshot (optional via CDP)
- cURL reproduction command
- CVSS estimate

## Integration with CDP Toolkit

For JavaScript-heavy targets:

```python
from cdp_toolkit import CDPClient

async with CDPClient(port=9224) as cdp:
    await cdp.navigate(url)
    cookies = await cdp.get_cookies()
    # Network interception for API endpoint discovery
```

## Related

- [bounty-hunter-toolkit on PyPI](https://pypi.org/project/bounty-hunter-toolkit/)
- [Bug Bounty Automation](bug-bounty-automation.md)
- [Freelance portfolio](https://ameobius-space.github.io/kwork-portfolio/)
