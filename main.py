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

    print_results(results)


def print_results(results):
    print("[+] RESULTADOS\n")

    for section, data in results.items():
        print(f"--- {section.upper()} ---")
        for key, value in data.items():
            print(f"{key}: {value}")
        print()


if __name__ == "__main__":
    main()