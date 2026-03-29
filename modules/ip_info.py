"""
IP information module.

Provides functionality to retrieve geolocation and ISP information
for a given IP address.
"""

import requests


def get_ip_info(ip):
    """
    Retrieve geolocation and ISP information for an IP address.

    Uses an external API to extract data such as country,
    region, city, and ISP.

    Args:
        ip (str): The target IP address.

    Returns:
        dict: Dictionary containing IP-related information or an error message.
    """
    data = {}

    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=5)
        info = response.json()

        data["country"] = info.get("country")
        data["region"] = info.get("regionName")
        data["city"] = info.get("city")
        data["isp"] = info.get("isp")

    except Exception as e:
        data["error"] = str(e)

    return data