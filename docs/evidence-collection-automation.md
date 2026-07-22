# Automating Evidence Collection for Bug Bounty Reports

> How to build reproducible evidence chains that triage teams accept
> on first read — using Python stdlib and CDP screenshots.

## Why Evidence Matters

A bug bounty report without evidence is a hypothesis. Triage teams
reject 40% of reports due to insufficient reproduction steps.
Automated evidence collection ensures every finding ships with:

- Full HTTP request/response pairs
- Screenshots (via CDP)
- cURL reproduction commands
- CVSS v3.1 estimate
- Affected parameter mapping

## Evidence Schema

```python
from bounty_hunter_toolkit import EvidenceCollector

collector = EvidenceCollector(output_dir="./findings")

evidence = collector.collect(
    url="https://target.com/api/users/1",
    method="GET",
    params={"id": "1' OR '1'='1"},
    vulnerability="SQL Injection",
    severity="critical"
)

# Evidence includes:
# - request.txt (raw HTTP request)
# - response.txt (raw HTTP response, status, headers, body)
# - screenshot.png (CDP capture, if available)
# - curl.sh (reproduction command)
# - report.json (structured finding)
```

## CDP Screenshot Integration

For JavaScript-rendered vulnerabilities:

```python
from cdp_toolkit import CDPClient

async with CDPClient(port=9224) as cdp:
    await cdp.navigate("https://target.com/profile")
    screenshot = await cdp.screenshot()
    # Attach to finding
```

## Reproducibility Checklist

Every evidence package must pass:

1. cURL command reproduces the vulnerability on a clean machine
2. Screenshot shows the impact (not just the payload)
3. Response includes the vulnerable data
4. No credentials leaked in evidence
5. CVSS estimate matches the actual impact

## Related

- [bounty-hunter-toolkit on PyPI](https://pypi.org/project/bounty-hunter-toolkit/)
- [Bug Bounty Automation](bug-bounty-automation.md)
- [Recon Pipeline with Python](recon-pipeline-with-python.md)
- [Freelance portfolio](https://ameobius-space.github.io/kwork-portfolio/)
