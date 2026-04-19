"""
Main entry point for the OSINT tool.

Orchestrates domain analysis including WHOIS, DNS records,
web fingerprinting, exposed files, emails, phones, leaks,
and subdomain enumeration.

Usage:
    python main.py <domain> [--passive | --active | --all]
"""

import sys
from modules.domain import get_domain_info
from modules.dns import get_dns_records
from modules.ip_info import get_ip_info
from modules.subdomains.passive import enumerate_passive
from modules.subdomains.active import enumerate_active
from modules.web_info import get_web_info
from modules.files import find_exposed_files
from modules.emails import extract_emails
from modules.phones import extract_phones
from modules.leaks import check_leaks


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <domain> [--passive | --active | --all]")
        return

    target = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "--all"

    print(f"\n[+] Target: {target}\n")

    results = {}

    # Core recon
    results["domain"] = get_domain_info(target)
    results["dns"] = get_dns_records(target)

    ip = results["dns"].get("A", [None])[0]
    results["ip_info"] = get_ip_info(ip) if ip else {"error": "No IP found"}

    # Web + exposure
    results["web_info"] = get_web_info(target)
    results["files"] = find_exposed_files(target)

    # Subdomains (run before emails/phones for better coverage)
    subdomains: set = set()

    if mode in ["--passive", "--all"]:
        print("[*] Running passive subdomain enumeration...")
        subdomains.update(enumerate_passive(target))

    if mode in ["--active", "--all"]:
        print("[*] Running active subdomain enumeration...")
        subdomains.update(enumerate_active(target, "wordlists/subdomains.txt"))

    results["subdomains"] = sorted(subdomains)

    # OSINT
    results["emails"] = extract_emails(target, results["subdomains"])
    results["phones"] = extract_phones(target, results["subdomains"])

    # Leaks
    results["leaks"] = check_leaks(results["emails"])

    # Output final
    print_results(results)


# =========================
# OUTPUT 
# =========================

def print_results(results: dict) -> None:
    print("\n[+] RESULTS\n")

    for section, data in results.items():
        status = get_section_status(section, data)
        print(f"[{status}] {section.upper()}")
        _print_section(section, data)
        print()


def get_section_status(section: str, data) -> str:
    """
    Generate visual status indicator for each section.
    """
    if not data:
        return "-"

    if section in ["emails", "phones", "files", "leaks"]:
        if isinstance(data, (list, dict)) and len(data) > 0:
            return "!"
        return "+"

    return "+"


def _print_section(section: str, data) -> None:

    # WEB INFO
    if section == "web_info" and isinstance(data, dict):
        print(f"  url:      {data.get('url')}")
        print(f"  status:   {data.get('status_code')}")
        print(f"  server:   {data.get('server')}")
        tech = data.get("technologies", [])
        print(f"  tech:     {', '.join(tech) if tech else '(none)'}")

    # FILES
    elif section == "files" and isinstance(data, dict):
        if not data:
            print("  (none)")
            return

        print(f"  Found: {len(data)}")

        for url, info in data.items():
            status = info.get("status")

            if status == 200:
                ct = info.get("content_type", "unknown")
                size = info.get("size", 0)

                print(f"  → {url}")
                print(f"    200 | {ct} | {size}b")

            elif status == 403:
                print(f"  → {url}")
                print(f"    403 | protected")

    # EMAILS / PHONES / SUBDOMAINS / LEAKS
    elif isinstance(data, list):
        if not data:
            print("  (none)")
            return

        print(f"  Found: {len(data)}")

        for item in data[:10]:
            print(f"  → {item}")

        if len(data) > 10:
            print(f"  ... ({len(data) - 10} more)")

    # GENERIC DICT (domain, dns, ip_info)
    elif isinstance(data, dict):
        for key, value in data.items():
            print(f"  {key}: {value}")

    else:
        print(f"  {data}")


if __name__ == "__main__":
    main()