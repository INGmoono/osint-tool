"""
DNS module.

Provides functionality to retrieve DNS records for a given domain.
"""

import dns.resolver


def get_dns_records(domain):
    """
    Retrieve DNS records for a given domain.

    Queries multiple DNS record types (A, MX, NS) and returns
    their values in a structured dictionary. If a record type
    cannot be resolved, an empty list is returned for that type.

    Args:
        domain (str): The target domain to query.

    Returns:
        dict: Dictionary containing DNS records categorized by type.
    """
    records = {}

    record_types = ["A", "MX", "NS"]

    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            records[record] = [r.to_text() for r in answers]
        except:
            records[record] = []

    return records