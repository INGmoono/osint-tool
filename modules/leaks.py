"""
Leak detection module.

Checks if emails associated with a domain have appeared
in known data breaches using public sources.
"""

import requests


HIBP_API = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"

HEADERS = {
    "User-Agent": "OSINT-Tool"
}


def check_hibp(email: str, api_key: str = None) -> dict:
    """
    Check if an email appears in known breaches using HIBP.

    Args:
        email (str): Email to check.
        api_key (str): Optional API key.

    Returns:
        dict: Breach info or error.
    """
    headers = HEADERS.copy()

    if api_key:
        headers["hibp-api-key"] = api_key

    try:
        response = requests.get(
            HIBP_API.format(email),
            headers=headers,
            timeout=5
        )

        if response.status_code == 200:
            return {
                "email": email,
                "breaches": [b["Name"] for b in response.json()]
            }

        elif response.status_code == 404:
            return None

        elif response.status_code == 401:
            return {"email": email, "error": "API key required"}

        else:
            return {"email": email, "error": f"HTTP {response.status_code}"}

    except requests.RequestException:
        return {"email": email, "error": "Request failed"}


def check_leaks(emails: list, api_key: str = None) -> list:
    """
    Check multiple emails for leaks.

    Args:
        emails (list): List of emails.
        api_key (str): Optional API key.

    Returns:
        list: Emails with breach data.
    """
    results = []

    for email in emails:
        result = check_hibp(email, api_key)

        if result and "breaches" in result:
            results.append(result)

    return results