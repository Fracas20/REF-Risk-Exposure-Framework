Shodan-Based Risk Exposure Framework (REF)
This repository contains a Python tool to assess cybersecurity risk for organizations based on real-world Internet exposure.
It integrates Shodan scans and Vulners exploit data to calculate Exposure (E), Likelihood (L), and Risk (R) scores.

Features
Queries Shodan for exposed IPs and services.

Extracts vulnerabilities (CVEs) and enriches them using Vulners API.

Calculates Exposure based on open ports and vulnerabilities.

Calculates Likelihood based on adversary interest, exploit availability, and vulnerability severity.

Outputs risk scores and highlights critical findings.

How It Works
Fetch data from Shodan using a specified organization or query.

Extract open ports, services, and CVEs.

Query Vulners to check exploit availability for each CVE.

Compute:

Exposure (E) = Number of vulnerable ports × Number of vulnerabilities × Number of vulnerable IPs.

Likelihood (L) = Adversary interest × (Exploits + VSI).

Risk (R) = Combination of E and L using an adjustable formula.

Export results in a structured report.

Requirements
Python 3.8+

Shodan API key

Vulners API key

Libraries: requests, pandas, shodan, math

Disclaimer:
This tool is intended for cybersecurity research and space-sector risk analysis.
Always ensure you have proper authorization to scan and assess external systems.
