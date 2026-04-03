"""
Main entry point for the OSINT tool.

Orchestrates domain analysis including WHOIS, DNS records,
and IP information retrieval.

Usage:
    python main.py <domain>
"""

import sys
from modules.domain import get_domain_info
from modules.dns import get_dns_records
from modules.ip_info import get_ip_info
from modules.subdomains.passive import enumerate_passive
from modules.subdomains.active import enumerate_active
from modules.web_info import get_web_info


def main():
    """
    Main execution function.

    Parses command-line arguments, performs OSINT analysis,
    and prints structured results.
    """
    if len(sys.argv) < 2:
        print("Use: python main.py <dominio>")
        return

    target = sys.argv[1]

    mode = sys.argv[2] if len(sys.argv) > 2 else "--all"

    print(f"\n[+] Target: {target}\n")

    results = {}

    # Domain
    results["domain"] = get_domain_info(target)

    # DNS
    results["dns"] = get_dns_records(target)

    # IP Info
    ip = results["dns"].get("A", [None])[0]
    if ip:
        results["ip_info"] = get_ip_info(ip)
    else:
        results["ip_info"] = {"error": "No IP encontrada"}

    # Web Info
    results["web_info"] = get_web_info(target)    

    # Subdomains
    subdomains = set()

    if mode in ["--passive", "--all"]:
        print("[+] Running passive subdomain enumeration...")
        passive = enumerate_passive(target)
        subdomains.update(passive)

    if mode in ["--active", "--all"]:
        print("[+] Running active subdomain enumeration...")
        active = enumerate_active(target, "wordlists/subdomains.txt")
        subdomains.update(active)

    results["subdomains"] = sorted(subdomains)

    print_results(results)


def print_results(results):
    print("[+] RESULTS\n")

    for section, data in results.items():
        print(f"--- {section.upper()} ---")

        if isinstance(data, dict):
            # 🔥 Caso especial: WEB_INFO
            if section == "web_info":
                print(f"url: {data.get('url')}")
                print(f"status_code: {data.get('status_code')}")
                print(f"server: {data.get('server')}")
                print(f"technologies: {data.get('technologies')}")
            
            else:
                for key, value in data.items():
                    print(f"{key}: {value}")
        elif isinstance(data, list):
            for item in data:
                print(item)
        else:
            print(data)

        print()

if __name__ == "__main__":
    main()