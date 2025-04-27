import shodan
import vulners
import pandas as pd
import concurrent.futures
from collections import Counter
import math

VULNERS_API_KEY = "VULNERS_API_KEY"
SHODAN_API_KEY = "SHODAN_API_KEY"

def get_shodan_data(shodan_api, query):
    """Query Shodan and return results."""
    try:
        return shodan_api.search(query)
    except Exception as e:
        print(f"Error querying Shodan: {e}")
        return {"matches": []}

def compute_exposure_score(ip_data, total_vulnerable_ips):
    """
    New Exposure Formula:
      E = ( Sum over IP of (OpenVulnPorts_IP * NumOfVulns_IP) ) * total_vulnerable_ips

    Returns:
      exposure_score,
      sum_term_for_debug (the sum of (OpenVulnPorts * NumOfVulns) across IPs)
    """
    if total_vulnerable_ips == 0:
        return 0, 0

    sum_term = 0
    for data in ip_data.values():
        sum_term += (data["OpenVulnPorts"] * data["NumOfVulnerabilities"])

    exposure_score = sum_term * total_vulnerable_ips
    return exposure_score, sum_term

def compute_likelihood(exploits_data, total_vulnerabilities, average_cvss_score):
    """Simple Likelihood (L) calculation, unchanged."""
    adversary_interest = 1  # Fixed
    exploit_availability = sum(exploits_data.values()) / total_vulnerabilities if total_vulnerabilities > 0 else 0
    likelihood = adversary_interest * (exploit_availability + average_cvss_score)
    return likelihood

def compute_risk_score(exposure_score, likelihood, c_weight=0.5):
    """
    Risk Calculation:
      risk_raw = c_weight * exposure_score + (1 - c_weight) * likelihood
      risk_scaled = log2(1 + risk_raw)
    """
    risk_raw = (c_weight * exposure_score) + ((1 - c_weight) * likelihood)
    risk_scaled = math.log2(1 + risk_raw) if risk_raw > 0 else 0
    return risk_raw, risk_scaled

def fetch_exploit_data_multithreaded(vulners_api, cve_list):
    """Fetch exploit data using multithreading to improve speed."""
    exploits_data = {}

    def fetch_single_cve(cve):
        try:
            return cve, len(vulners_api.find_exploit_all(cve, limit=500) or [])
        except:
            return cve, 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(fetch_single_cve, cve_list)

    for cve, count in results:
        exploits_data[cve] = count
    return exploits_data

def analyze_org_security(SHODAN_API_KEY, VULNERS_API_KEY, org_name):
    """
    Main function with new exposure formula:
      E = ( sum_{IP} (OpenVulnPorts_IP * NumOfVulns_IP) ) * total_vulnerable_ips

    We'll print each part so we can debug:
      - open vuln ports per IP
      - number of vulnerabilities per IP
      - the sum_term
      - the final exposure
    """
    shodan_api = shodan.Shodan(SHODAN_API_KEY)
    vulners_api = vulners.VulnersApi(api_key=VULNERS_API_KEY)

    print(f"Querying Shodan for total exposed IPs in {org_name}")
    total_exposed_ips = shodan_api.count(f'org:"{org_name}"')['total']

    print(f"Querying Shodan for total vulnerable IPs in {org_name}")
    total_vulnerable_ips = shodan_api.count(f'org:"{org_name}" has_vuln:"true"')['total']

    print(f"Querying Shodan for details on vulnerable hosts in {org_name}")
    vuln_results = get_shodan_data(shodan_api, f'org:"{org_name}" has_vuln:"true"')

    ip_data = {}
    all_cves = []
    all_cvss_scores = []
    all_cpes = []
    total_open_ports = 0
    unique_cves = set()
    unique_cpes = Counter()

    for result in vuln_results.get('matches', []):
        ip_address = result.get("ip_str", "Unknown")

        # Retrieve full host info
        try:
            host_info = shodan_api.host(ip_address)
        except Exception as e:
            print(f"[ERROR] Could not retrieve host info for {ip_address}: {e}")
            continue

        # Ports
        # tracks the ports that are 'vulnerable', i.e. associated with at least 1 CVE
        vuln_ports_set = set()
        for service in host_info.get("data", []):
            port_num = service.get("port", None)
            # if service has 'vulns', then that port is 'open and vuln'
            if port_num is not None and "vulns" in service and len(service["vulns"]) > 0:
                vuln_ports_set.add(port_num)

        open_vuln_ports = len(vuln_ports_set)  # how many open ports have known CVE
        total_open_ports += open_vuln_ports  # count them globally

        cve_list = list(result.get("vulns", {}).keys())
        cvss_list = [
            result["vulns"][cve].get("cvss", 0)
            for cve in cve_list if "cvss" in result["vulns"][cve]
        ]
        all_cvss_scores.extend(cvss_list)

        # Extract CPEs from the host data
        cpe_list = []
        for service in host_info.get("data", []):
            if "cpe" in service:
                cpe_list.extend(service["cpe"])
        unique_cpes.update(cpe_list)
        all_cpes.extend(cpe_list)

        ip_data[ip_address] = {
            "OpenVulnPorts": open_vuln_ports,  #  new exposure formula
            "Vulnerabilities": cve_list,
            "NumOfVulnerabilities": len(cve_list),
            "Exploits": 0,
            "CVSS Score": sum(cvss_list)/len(cvss_list) if cvss_list else 0,
            "CPEs": cpe_list
        }

        all_cves.extend(cve_list)
        unique_cves.update(cve_list)

    # Fetch exploit data for all unique CVEs
    print("Fetching exploit data from Vulners API using multithreading...")
    exploits_data = fetch_exploit_data_multithreaded(vulners_api, list(unique_cves))

    # Update exploit count per IP
    for ip, data in ip_data.items():
        cves_for_ip = data["Vulnerabilities"]
        data["Exploits"] = sum(exploits_data.get(cve, 0) for cve in cves_for_ip)

    average_cvss_score = 0
    if len(all_cvss_scores) > 0:
        average_cvss_score = sum(all_cvss_scores) / len(all_cvss_scores)

    total_vulnerabilities = len(all_cves)
    #  compute the new exposure
    exposure_score, sum_term = compute_exposure_score(ip_data, total_vulnerable_ips)

    # Likelihood
    likelihood = compute_likelihood(exploits_data, total_vulnerabilities, average_cvss_score)

    # Risk
    risk_raw, risk_scaled = compute_risk_score(exposure_score, likelihood)

    # Gather top CVEs
    most_common_cves = Counter(all_cves).most_common(10)
    total_exploits = sum(exploits_data.values())

    # Build DataFrame
    summary_df = pd.DataFrame([{
        "Organization": org_name,
        "Total Exposed IPs": total_exposed_ips,
        "Total Vulnerable IPs": total_vulnerable_ips,
        "Total Unique CVEs": len(unique_cves),
        "Total Exploits": total_exploits,
        # Summation of (OpenVulnPorts * NumOfVulns) across all IPs
        "SumTerm (OpenVulnPorts*NOfVulns)": sum_term,
        "Exposure Score": round(exposure_score, 2),
        "Likelihood Score": round(likelihood, 2),
        "Risk Raw": round(risk_raw, 2),
        "Risk Scaled (Avg)": round(risk_scaled, 2),
        "Risk Scaled (Weighted)": round(risk_scaled, 2),
        "Average CVSS Score": round(average_cvss_score, 2),
        "Total 'Open Vuln Ports' (Global)": total_open_ports
    }])

    # Build top 10 IPs DF (sort by # of open vuln ports, then # of vulnerabilities, etc.)
    top_vulnerable_ips_df = pd.DataFrame([
        {
            "IP": ip,
            "OpenVulnPorts": data["OpenVulnPorts"],
            "NumOfVulnerabilities": data["NumOfVulnerabilities"],
            "Exploits": data["Exploits"],
            "CVSS Score": data["CVSS Score"]
        }
        for ip, data in sorted(
            ip_data.items(),
            key=lambda x: (x[1]["OpenVulnPorts"], x[1]["NumOfVulnerabilities"], x[1]["CVSS Score"], x[1]["Exploits"]),
            reverse=True
        )[:10]
    ])


    top_cpes_df = pd.DataFrame(Counter(all_cpes).most_common(10), columns=["CPE", "Count"])

    return summary_df, top_vulnerable_ips_df, top_cpes_df, most_common_cves

# usage:
# summary_df, top_ips_df, top_cpes_df, cves = analyze_org_security(SHODAN_API_KEY, VULNERS_API_KEY, "SpaceX")
# display(summary_df)
# display(top_ips_df)
# display(top_cpes_df)
# print("Top 10 CVEs:", cves)
