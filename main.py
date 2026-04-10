"""
Main entry point for the OSINT tool.
Orchestrates domain analysis including WHOIS, DNS records,
and IP information retrieval.

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


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <domain> [--passive | --active | --all]")
        return

    target = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "--all"

    print(f"\n[+] Target: {target}\n")

    results = {}

    results["domain"] = get_domain_info(target)
    results["dns"] = get_dns_records(target)

    ip = results["dns"].get("A", [None])[0]
    results["ip_info"] = get_ip_info(ip) if ip else {"error": "No IP found"}

    results["web_info"] = get_web_info(target)
    results["files"] = find_exposed_files(target)
    results["emails"] = extract_emails(target, [])
    results["phones"] = extract_phones(target, [])

    # Subdomains — run after everything else since enumeration can be slow
    subdomains: set = set()
    if mode in ["--passive", "--all"]:
        print("[*] Running passive subdomain enumeration...")
        subdomains.update(enumerate_passive(target))
    if mode in ["--active", "--all"]:
        print("[*] Running active subdomain enumeration...")
        subdomains.update(enumerate_active(target, "wordlists/subdomains.txt"))

    results["subdomains"] = sorted(subdomains)

    print_results(results)


def print_results(results: dict) -> None:
    print("\n[+] RESULTS\n")

    for section, data in results.items():
        print(f"--- {section.upper()} ---")
        _print_section(section, data)
        print()


def _print_section(section: str, data) -> None:
    if section == "web_info" and isinstance(data, dict):
        print(f"  url:          {data.get('url')}")
        print(f"  status_code:  {data.get('status_code')}")
        print(f"  server:       {data.get('server')}")
        print(f"  technologies: {data.get('technologies')}")

    elif section == "files" and isinstance(data, dict):
        if not data:
            print("  No exposed files found.")
            return
        for url, info in data.items():
            status = info.get("status")
            category = info.get("category", "").upper()
            note = info.get("note")

            if status == 200:
                ct = info.get("content_type", "unknown")
                size = info.get("size", 0)
                snippet = info.get("snippet", "").replace("\n", " ").strip()
                if len(snippet) > 80:
                    snippet = snippet[:80] + "..."
                print(f"  [{category}] {url}")
                print(f"    status: 200  type: {ct}  size: {size}b")
                print(f"    preview: {snippet}")
            else:
                print(f"  [{category}] {url}")
                print(f"    status: {status}  {note}")

    elif isinstance(data, dict):
        for key, value in data.items():
            print(f"  {key}: {value}")

    elif isinstance(data, list):
        if not data:
            print("  (none)")
        for item in data:
            print(f"  {item}")

    else:
        print(f"  {data}")


if __name__ == "__main__":
    main()