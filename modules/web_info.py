"""
Web information module.

Provides functionality to extract HTTP headers and identify
basic technologies used by a target website.
"""

import requests


def get_web_info(domain: str) -> dict:
    """
    Retrieve web information from a target domain.

    Performs an HTTP request and extracts headers, server
    information, and basic technology indicators.

    Args:
        domain (str): Target domain.

    Returns:
        dict: Dictionary containing web-related information.
    """
    data = {}

    urls = [
        f"http://{domain}",
        f"https://{domain}"
    ]

    for url in urls:
        try:
            response = requests.get(url, timeout=5)

            data["url"] = url
            data["status_code"] = response.status_code

            # Headers
            data["headers"] = dict(response.headers)

            # Server
            data["server"] = response.headers.get("Server")

            # Technologies (fingerprinting)
            technologies = []

            # 🔹 Headers
            if "X-Powered-By" in response.headers:
                technologies.append(response.headers["X-Powered-By"])

            if "Server" in response.headers:
                technologies.append(response.headers["Server"])

            # 🔹 Cookies
            if "set-cookie" in response.headers:
                cookie = response.headers["set-cookie"].lower()

                if "php" in cookie:
                    technologies.append("PHP")

                if "laravel" in cookie:
                    technologies.append("Laravel")

                if "django" in cookie:
                    technologies.append("Django")

                if "frontend=" in cookie:
                    technologies.append("Magento")

            # 🔹 HTML Fingerprinting
            html = response.text.lower()

            if "wp-content" in html:
                technologies.append("WordPress")

            if "django" in html:
                technologies.append("Django")

            if "react" in html:
                technologies.append("React")

            if "vue" in html:
                technologies.append("Vue")

            if "astro" in html:
                technologies.append("Astro")

            if "flask" in html:
                technologies.append("Flask")

            # Remove duplicates
            data["technologies"] = list(set(technologies))

            return data

        except requests.RequestException:
            continue

    return {"error": "Failed to connect to target"}