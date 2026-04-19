"""
Passive subdomain enumeration module.

Uses certificate transparency logs (crt.sh).
"""

import requests
import time


def enumerate_passive(domain: str) -> list:
    """
    Retrieve subdomains using crt.sh.
    """
    import requests
    import time

    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    for attempt in range(3):
        try:
            print(f"[PASSIVE] Attempt {attempt + 1}...")

            response = requests.get(url, headers=headers, timeout=15)

            if response.status_code != 200:
                print(f"[PASSIVE] HTTP {response.status_code}")
                time.sleep(3)
                continue

            if "application/json" not in response.headers.get("Content-Type", ""):
                print("[PASSIVE] Invalid response (not JSON)")
                time.sleep(3)
                continue

            data = response.json()

            for entry in data:
                names = entry.get("name_value", "").split("\n")

                for name in names:
                    name = name.strip()

                    if name and "*" not in name:
                        subdomains.add(name)

            return sorted(subdomains)

        except requests.RequestException as e:
            print(f"[PASSIVE] Request error: {e}")
            time.sleep(3)

        except ValueError:
            print("[PASSIVE] JSON parsing error")
            time.sleep(3)

    return ["Error: Failed to retrieve crt.sh data"]