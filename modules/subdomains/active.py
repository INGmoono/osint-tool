"""
Active subdomain enumeration module.

Performs DNS brute-force using a wordlist with multithreading.
"""

import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed


def _resolve_subdomain(full_domain: str) -> str | None:
    """
    Attempt to resolve a subdomain.

    Args:
        full_domain (str): Full subdomain.

    Returns:
        str | None: Subdomain if valid, otherwise None.
    """
    try:
        dns.resolver.resolve(full_domain, "A")
        return full_domain
    except Exception:
        return None


def enumerate_active(domain: str, wordlist_path: str, threads: int = 30) -> list:
    """
    Perform active subdomain enumeration via brute-force.

    Args:
        domain (str): Target domain.
        wordlist_path (str): Path to wordlist.
        threads (int): Number of concurrent threads.

    Returns:
        list: Discovered subdomains.
    """
    discovered = []

    try:
        with open(wordlist_path, "r") as file:
            words = file.read().splitlines()
    except Exception as e:
        return [f"Error loading wordlist: {e}"]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []

        for word in words:
            full_domain = f"{word}.{domain}"
            futures.append(executor.submit(_resolve_subdomain, full_domain))

        for future in as_completed(futures):
            result = future.result()
            if result:
                print(f"[ACTIVE] Found: {result}")
                discovered.append(result)

    return discovered