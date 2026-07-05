# Vulnerability Intelligence Prioritizer

Vulnerability Intelligence Prioritizer ranks vulnerabilities by severity, known exploitation, internet exposure, and asset criticality. It turns a flat CVE list into an action plan.

## Why Employers Like This

Real security teams cannot patch everything instantly. They need risk-based prioritization. This project shows vulnerability management thinking, business context, and remediation SLAs.

## Features

- Loads vulnerability data from JSON.
- Combines CVSS, exploitation status, exposure, and asset criticality.
- Produces a priority score.
- Assigns remediation SLAs.
- Exports a Markdown report.
- Includes tests and sample data.

## Example Report

See [docs/examples/example_vulnerability_priorities.md](docs/examples/example_vulnerability_priorities.md) for a rendered sample prioritization report.

## Quick Start

```bash
set PYTHONPATH=src
python -m vuln_intel_prioritizer.cli
python -m unittest discover -s tests -v
```

## Skills Demonstrated

- Vulnerability management
- Risk scoring
- Asset criticality modeling
- Python data processing
- Security reporting

## Responsible Use

This tool supports defensive prioritization and does not scan or exploit systems.
