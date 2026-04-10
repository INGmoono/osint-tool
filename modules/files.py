"""
Files and metadata discovery module.
Discovers exposed files and reduces false positives through content validation.
"""

import re
import requests

# Paths grouped by sensitivity for structured reporting
COMMON_PATHS = {
    "sensitive": [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.git/config",
        "/.git/HEAD",
        "/config.php",
        "/config.yml",
        "/config.yaml",
        "/wp-config.php",
        "/database.yml",
        "/.htpasswd",
        "/credentials.json",
        "/secrets.json",
    ],
    "backup": [
        "/backup.zip",
        "/backup.tar.gz",
        "/backup.sql",
        "/dump.sql",
        "/db.sql",
        "/www.zip",
        "/site.tar.gz",
    ],
    "info": [
        "/robots.txt",
        "/sitemap.xml",
        "/security.txt",
        "/.well-known/security.txt",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
    ],
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "Chrome/120.0 Safari/537.36"
    )
}

# Minimum byte size for a response to be considered real content.
# Servers that return empty 200s or near-empty catch-all pages are rejected.
MIN_CONTENT_SIZE = 20

# HTML signals that indicate a catch-all / soft 404 page rather than a real file
HTML_FALSE_POSITIVE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"<!doctype html",
        r"<html",
        r"404",
        r"not found",
        r"page not found",
        r"doesn.t exist",
        r"no existe",
        r"error",
    ]
]

# Content-type prefixes that indicate a real file (not an HTML error page)
VALID_CONTENT_TYPES = (
    "text/plain",
    "application/json",
    "application/xml",
    "text/xml",
    "application/x-www-form-urlencoded",
    "application/octet-stream",
    "application/zip",
    "application/x-tar",
    "application/x-gzip",
    "application/sql",
)

# Known values returned by servers for non-existent paths — used to detect
# soft 404s by comparing the baseline response against each discovered path.
BASELINE_PATHS = ["/this-path-does-not-exist-osint-check-xyz123"]


def _get_baseline(base_url: str) -> tuple[int, str]:
    """
    Fetch a guaranteed-nonexistent path to fingerprint the server's 404 behavior.
    Returns (status_code, body_snippet) for comparison against real requests.
    """
    try:
        r = requests.get(
            f"{base_url}{BASELINE_PATHS[0]}",
            headers=HEADERS,
            timeout=6,
            allow_redirects=False,
        )
        return r.status_code, r.text[:200].strip().lower()
    except requests.RequestException:
        return 404, ""


def _is_soft_404(response: requests.Response, baseline_body: str) -> bool:
    """
    Detect servers that return HTTP 200 for every URL (soft 404 / catch-all).
    Compares the response body snippet against the known baseline 404 body.
    """
    body_snippet = response.text[:200].strip().lower()

    # If the body is virtually identical to the baseline, it's a catch-all
    if baseline_body and body_snippet == baseline_body:
        return True

    return False


def _is_html_error_page(response: requests.Response) -> bool:
    """
    Return True if the response body looks like an HTML error or catch-all page
    rather than the actual file content.
    """
    body = response.text.strip()

    if not body:
        return True

    # Check the first 300 chars for HTML error indicators
    head = body[:300].lower()
    return any(p.search(head) for p in HTML_FALSE_POSITIVE_PATTERNS)


def _validate_200(
    response: requests.Response,
    path: str,
    baseline_body: str,
) -> dict | None:
    """
    Apply false-positive filters to a 200 response and return a result dict
    if the file is genuinely accessible, or None if it looks like a fake hit.

    Filters applied:
      1. Soft 404 detection — body matches baseline non-existent path response
      2. Minimum size — near-empty responses are likely placeholder pages
      3. Content-type check — prefer non-HTML types; HTML is allowed only for
         known text files (robots.txt, sitemap.xml, security.txt)
      4. HTML error pattern scan — rejects catch-all pages that slip through
    """
    content_type = response.headers.get("Content-Type", "").lower()
    body = response.text

    # Filter 1: soft 404
    if _is_soft_404(response, baseline_body):
        return None

    # Filter 2: minimum content size
    if len(body.strip()) < MIN_CONTENT_SIZE:
        return None

    # Filter 3: content-type
    is_text_file = any(path.endswith(ext) for ext in (".txt", ".xml"))
    if "text/html" in content_type and not is_text_file:
        return None

    if not is_text_file and not any(
        content_type.startswith(ct) for ct in VALID_CONTENT_TYPES
    ):
        # If content-type is ambiguous, fall through to body inspection
        if _is_html_error_page(response):
            return None

    # Filter 4: body content scan for text-based files
    if is_text_file and _is_html_error_page(response):
        return None

    return {
        "status": 200,
        "content_type": content_type.split(";")[0].strip(),
        "size": len(body),
        "snippet": body.strip()[:120],
    }


def find_exposed_files(domain: str) -> dict:
    """
    Search for exposed files across sensitive, backup, and info path categories.

    For each candidate URL:
      - HTTP 200: validated through 4 false-positive filters before reporting
      - HTTP 403: reported as protected (file likely exists but is restricted)
      - HTTP 401: reported as authentication-protected
      - Redirects and other codes: silently skipped

    Args:
        domain: Target domain (e.g. "example.com")

    Returns:
        Dict keyed by URL with status, metadata, and a short content snippet.
        Example:
            {
                "https://example.com/robots.txt": {
                    "status": 200,
                    "category": "info",
                    "content_type": "text/plain",
                    "size": 42,
                    "snippet": "User-agent: *\nDisallow: /admin"
                }
            }
    """
    found: dict = {}

    # Prefer HTTPS; fall back to HTTP only if HTTPS is unreachable
    schemes = ["https", "http"]

    for scheme in schemes:
        base = f"{scheme}://{domain}"

        # Fingerprint server's 404 behavior before scanning
        baseline_status, baseline_body = _get_baseline(base)

        reachable = False

        for category, paths in COMMON_PATHS.items():
            for path in paths:
                url = f"{base}{path}"

                # Skip if already found via the other scheme
                normalized = url.replace("http://", "https://")
                if normalized in found or url in found:
                    continue

                try:
                    response = requests.get(
                        url,
                        headers=HEADERS,
                        timeout=6,
                        allow_redirects=False,
                    )
                    reachable = True
                    status = response.status_code

                    if status in (301, 302, 303, 307, 308):
                        continue

                    if status == 200:
                        result = _validate_200(response, path, baseline_body)
                        if result:
                            result["category"] = category
                            found[url] = result

                    elif status == 403:
                        found[url] = {
                            "status": 403,
                            "category": category,
                            "note": "Forbidden — file likely exists but is restricted",
                        }

                    elif status == 401:
                        found[url] = {
                            "status": 401,
                            "category": category,
                            "note": "Unauthorized — authentication required",
                        }

                except requests.RequestException:
                    continue

        # If HTTPS was reachable, skip HTTP to avoid duplicate entries
        if reachable:
            break

    return found