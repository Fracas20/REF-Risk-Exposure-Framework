import shodan
import vulners
import pandas as pd
import concurrent.futures
from collections import Counter
import math

VULNERS_API_KEY = "LNLSZ1BD0RC3759P4OQORKYVYG0UY2YCJUSF75MO4PL8LYCJXTAZIL31C60WY04C"
SHODAN_API_KEY = "TIH2vcAVn8hj3zAVXYdhkHNQEZJy3KxW"

def get_shodan_data(shodan_api, query):
    try:
        return shodan_api.search(query)
    except Exception as e:
        print(f"Error querying Shodan: {e}")
        return {"matches": []}

def compute_exposure_score(ip_data):
    if not ip_data:
        return 0
    total_v = sum(data["NumOfVulnerabilities"] for data in ip_data.values())
    return total_v / len(ip_data)

def compute_ea_score(ip_data, exploits_data):
    ea_total = 0
    counted_ips = 0
    for data in ip_data.values():
        cves = data["Vulnerabilities"]
        if not cves:
            continue
        exploited = sum(1 for cve in cves if exploits_data.get(cve, 0) > 0)
        ea_ip = exploited / len(cves)
        ea_total += ea_ip
        counted_ips += 1
    return ea_total / counted_ips if counted_ips else 0

def compute_likelihood(exploits_data, total_vulnerabilities, average_cvss_score):
    adversary_interest = 1
    exploit_availability = sum(exploits_data.values()) / total_vulnerabilities if total_vulnerabilities > 0 else 0
    return adversary_interest * (exploit_availability + average_cvss_score)

def compute_risk_score(exposure_score, likelihood, c_weight=0.5):
    risk_raw = (c_weight * exposure_score) + ((1 - c_weight) * likelihood)
    risk_scaled = math.log2(1 + risk_raw) if risk_raw > 0 else 0
    return risk_raw, risk_scaled

def fetch_exploit_data_multithreaded(vulners_api, cve_list):
    exploits_data = {}

    def fetch_single_cve(cve):
        try:
            results = vulners_api.search.search_exploits_all(cve, limit=50)
            return cve, len(results) if results else 0
        except Exception as e:
            print(f"Error fetching {cve}: {e}")
            return cve, 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(fetch_single_cve, cve_list)

    for cve, count in results:
        exploits_data[cve] = count

    return exploits_data

def analyze_org_security(SHODAN_API_KEY, VULNERS_API_KEY, org_name):
    shodan_api = shodan.Shodan(SHODAN_API_KEY)
    vulners_api = vulners.VulnersApi(api_key=VULNERS_API_KEY)

    print(f"Querying Shodan for exposed IPs in {org_name}")
    total_exposed_ips = shodan_api.count(f'org:"{org_name}"')['total']

    print(f"Querying Shodan for vulnerable IPs in {org_name}")
    total_vulnerable_ips = shodan_api.count(f'org:"{org_name}" has_vuln:"true"')['total']

    print(f"Querying Shodan for vulnerable hosts in {org_name}")
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
        try:
            host_info = shodan_api.host(ip_address)
        except Exception as e:
            print(f"[ERROR] Could not retrieve host info for {ip_address}: {e}")
            continue

        vuln_ports_set = set()
        for service in host_info.get("data", []):
            port_num = service.get("port", None)
            if port_num is not None and "vulns" in service and len(service["vulns"]) > 0:
                vuln_ports_set.add(port_num)

        open_vuln_ports = len(vuln_ports_set)
        total_open_ports += open_vuln_ports

        cve_list = list(result.get("vulns", {}).keys())
        cvss_list = [
            result["vulns"][cve].get("cvss", 0)
            for cve in cve_list if "cvss" in result["vulns"][cve]
        ]
        all_cvss_scores.extend(cvss_list)

        cpe_list = []
        for service in host_info.get("data", []):
            if "cpe" in service:
                cpe_list.extend(service["cpe"])
        unique_cpes.update(cpe_list)
        all_cpes.extend(cpe_list)

        ip_data[ip_address] = {
            "OpenVulnPorts": open_vuln_ports,
            "Vulnerabilities": cve_list,
            "NumOfVulnerabilities": len(cve_list),
            "CVSS Score": sum(cvss_list)/len(cvss_list) if cvss_list else 0,
            "CPEs": cpe_list
        }

        all_cves.extend(cve_list)
        unique_cves.update(cve_list)

    exploits_data = fetch_exploit_data_multithreaded(vulners_api, list(unique_cves))
    for ip, data in ip_data.items():
        cves_for_ip = data["Vulnerabilities"]
        data["Exploits"] = sum(exploits_data.get(cve, 0) for cve in cves_for_ip)

    average_cvss_score = sum(all_cvss_scores) / len(all_cvss_scores) if all_cvss_scores else 0
    total_vulnerabilities = len(all_cves)
    exposure_score = compute_exposure_score(ip_data)
    ea_score = compute_ea_score(ip_data, exploits_data)
    likelihood = compute_likelihood(exploits_data, total_vulnerabilities, average_cvss_score)
    risk_raw, risk_scaled = compute_risk_score(exposure_score, likelihood)

    summary_df = pd.DataFrame([{
        "Organization": org_name,
        "Total Unique CVEs": len(unique_cves),
        "Total Exposed IPs": total_exposed_ips,
        "Total Vulnerable IPs": total_vulnerable_ips,
        "Total Exploits": sum(exploits_data.values()),
        "Exposure Score": round(exposure_score, 2),
        "EA Score": round(ea_score, 2),
        "Likelihood Score": round(likelihood, 2),
        "Risk Raw": round(risk_raw, 2),
        "Risk Scaled": round(risk_scaled, 2),
        "Average CVSS Score": round(average_cvss_score, 2),
        "Total 'Open Vuln Ports' (Global)": total_open_ports
    }])

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
    return summary_df, top_vulnerable_ips_df, top_cpes_df, Counter(all_cves).most_common(10)
