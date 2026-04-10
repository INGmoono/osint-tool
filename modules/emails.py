"""
Email extraction module.

Performs robust email discovery across a domain and its subdomains
using multiple paths and realistic request headers.
"""

import re
import requests


COMMON_PATHS = [
    "",
    "/contact",
    "/contacto",
    "/about",
    "/about-us",
    "/legal",
    "/privacy",
    "/terms"
]


HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
}


def extract_emails(domain: str, subdomains: list = None) -> list:
    """
    Extract emails from a domain and its subdomains.

    Args:
        domain (str): Target domain.
        subdomains (list): List of subdomains.

    Returns:
        list: Unique discovered email addresses.
    """
    emails = set()
    visited = set()

    # Targets: root domain + subdomains
    targets = {domain}
    if subdomains:
        targets.update(subdomains)

    # Regex estricta para el dominio objetivo
    pattern = re.compile(
        r"[a-zA-Z0-9._%+-]+@" + re.escape(domain),
        re.IGNORECASE
    )

    for target in targets:
        for scheme in ["http", "https"]:
            base = f"{scheme}://{target}"

            for path in COMMON_PATHS:
                url = f"{base}{path}"

                # evitar repetir requests
                if url in visited:
                    continue
                visited.add(url)

                try:
                    response = requests.get(
                        url,
                        headers=HEADERS,
                        timeout=5
                    )

                    # solo procesar HTML válido
                    content_type = response.headers.get("Content-Type", "").lower()
                    if "text/html" not in content_type:
                        continue

                    html = response.text

                    matches = pattern.findall(html)

                    for email in matches:
                        emails.add(email.lower())

                except requests.RequestException:
                    continue

    return sorted(emails)