"""
Domain module.

Provides functionality to retrieve WHOIS information for a given domain.
"""

import whois


def get_domain_info(domain):
    """
    Retrieve WHOIS information for a domain.

    Extracts relevant fields such as domain name, registrar,
    creation date, and expiration date.

    Args:
        domain (str): The target domain.

    Returns:
        dict: Dictionary containing domain information or an error message.
    """
    data = {}

    try:
        w = whois.whois(domain)

        data["domain name"] = w.domain_name
        data["registrar"] = w.registrar
        data["creation date"] = str(w.creation_date)
        data["expiration date"] = str(w.expiration_date)

    except Exception as e:
        data["error"] = str(e)

    return data