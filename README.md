# Shodan-Based Risk Exposure Framework (REF)

A Python tool to assess cybersecurity risk for organizations based on real-world Internet exposure.  
It integrates Shodan scans and Vulners exploit data to calculate Exposure (E), Likelihood (L), and Risk (R) scores.

---

## What Is REF and Why It’s Useful

REF (Risk Exposure Framework) is designed to give security researchers and space-sector engineers a clear, quantitative view of an organization’s external attack surface. By combining data from Shodan (to find exposed IPs, open ports, and associated CVEs) with exploit-availability information from the Vulners API, REF computes three core metrics:  

- **Exposure (E):** How widespread and severe the vulnerabilities are, based on open vulnerable ports and CVE counts.  
- **Likelihood (L):** The probability of an attack succeeding, driven by adversary interest, available exploits, and CVSS severity.  
- **Risk (R):** A normalized score that fuses Exposure and Likelihood into a single, actionable number.

REF is particularly useful for:  
- Identifying high-risk hosts and services in real time.  
- Prioritizing patching and mitigation efforts.  
- Benchmarking an organization’s cybersecurity posture over time.  
- Supporting space-sector stakeholders in managing their unique threat landscape.

---

## Features

- **Shodan Integration:** Automatically query Shodan for all IPs under a given organization (or custom query).  
- **Vulnerability Extraction:** Parse CVEs from Shodan’s host data and calculate counts of open vulnerable ports.  
- **Vulners Enrichment:** For each CVE, determine exploit availability via the Vulners API (multithreaded fetch).  
- **Exposure Calculation:**  
  \[
    E \;=\;\Bigl(\sum_{\text{each IP}} \bigl(\text{OpenVulnPorts} \times \text{NumOfVulns}\bigr)\Bigr)\;\times\;\text{(total vulnerable IPs)}
  \]
- **Likelihood Calculation:**  
  \[
    L \;=\; \text{adversary interest} \;\times\; \bigl(\text{exploit availability} + \text{average CVSS}\bigr)
  \]
- **Risk Scoring:**  
  \[
    R_{\text{raw}} = c \times E + (1 - c) \times L,\quad
    R_{\text{scaled}} = \log_2(1 + R_{\text{raw}})
  \]
- **Structured Output:** Summarizes total exposed/vulnerable IPs, unique CVEs, exploit counts, individual host rankings, and top CPEs.  
- **Configurable:** Easily adjust weighting (c-weight) or scan filters to tailor to different operational needs.

---

## Requirements

- **Python 3.8+**  
- **Shodan API Key**  
- **Vulners API Key**  

### Python Libraries

- `shodan`
- `vulners`
- `pandas`
- `requests`
- `concurrent.futures` (standard library)
- `collections` (standard library)
- `math` (standard library)

---


