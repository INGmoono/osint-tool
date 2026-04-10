"""
Phone number extraction module.
Extracts and filters real phone numbers using multi-layer detection.

Requirements:
    pip install requests phonenumbers beautifulsoup4
"""

import re
import requests
import phonenumbers
from phonenumbers import PhoneNumberMatcher, PhoneNumberFormat, is_valid_number
from bs4 import BeautifulSoup

COMMON_PATHS = ["", "/contact", "/contacto", "/about", "/about-us", "/nosotros"]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "Chrome/120.0 Safari/537.36"
    )
}

# Default region for local numbers without international prefix
DEFAULT_REGION = "CO"

# Layer 1 — Strict contextual regex.
# Matches real phone-formatted strings only:
#   +57 300 123 4567 | (601) 234-5678 | 300-123-4567 | +1 (800) 555-1234
# Rejects: bare digit runs (1234567890), IPs (3.14.159.265), dates (2024-01-15)
PHONE_REGEX = re.compile(
    r"""
    (?<!\d)
    (
        \+\d{1,3}[\s\-\.]?        # Optional international prefix (+57, +1)
        [\(\s]?\d{1,4}[\)\s]?     # Optional area code
        [\s\-\.]                  # Required separator — rejects unseparated digit runs
        \d{3,5}
        [\s\-\.]?
        \d{3,5}
    |
        \(\d{2,4}\)               # Area code in parentheses
        [\s\-\.]\d{3,5}
        [\s\-\.]?\d{3,5}
    )
    (?!\d)
    """,
    re.VERBOSE,
)

# Layer 3 — Blacklist patterns that are never phone numbers
BLACKLIST_PATTERNS = [
    re.compile(p) for p in [
        r"^\+?1?\s?800\s?555",          # Hollywood fake numbers
        r"^(19|20)\d{2}[-/]\d{2}",      # Dates: 2024-01-15
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses: 192.168.1.1
        r"v?\d+\.\d+\.\d+",             # Version strings: v1.2.3
        r"^\d{13,}$",                   # EAN barcodes and long numeric IDs
        r"^0{4,}",                      # Strings starting with many zeros
        r"\d{4}-\d{4}-\d{4}-\d{4}",    # Credit card numbers
        r"^\d{2}/\d{2}/\d{4}",         # Dates: 01/01/2024
        r"#\d+",                        # Fragment IDs: #123
        r"order[_-]?\d+",               # Order IDs
        r"ref[_-]?\d+",                 # Reference IDs
        r"id[_-]?\d+",                  # Generic IDs
    ]
]

# Layer 4 — HTML attributes that explicitly mark a value as a phone number
PHONE_ATTRS = {"href", "data-phone", "data-tel", "data-number", "aria-label", "title"}

# Keywords used to detect phone-related context in surrounding text and attributes
CONTEXT_KEYWORDS = [
    "phone", "tel", "fax", "cel", "celular", "movil", "mobile",
    "contact", "contacto", "whatsapp", "llamar", "telefono", "numero", "call",
]

CONTEXT_KEYWORD_RE = re.compile(r"|".join(CONTEXT_KEYWORDS), re.IGNORECASE)


def _digit_only(text: str) -> str:
    return re.sub(r"\D", "", text)


def passes_basic_checks(raw: str) -> bool:
    """Layer 2: digit count and quality sanity checks."""
    digits = _digit_only(raw)

    # Realistic length: 7 (short local) to 15 (E.164 maximum)
    if not (7 <= len(digits) <= 15):
        return False

    # Reject repetitive digit strings (00000000, 11111111)
    if len(set(digits)) <= 3:
        return False

    # Reject perfect ascending/descending sequences
    if digits in ("1234567890", "0987654321", "12345678", "87654321"):
        return False

    return True


def passes_blacklist(raw: str) -> bool:
    """Layer 3: reject strings that match known non-phone patterns."""
    return not any(p.search(raw.strip()) for p in BLACKLIST_PATTERNS)


def has_html_context(tag, soup: BeautifulSoup, raw: str) -> bool:
    """
    Layer 4: confirm the number appears in a phone-related HTML context.

    Checks in priority order:
      A. href="tel:..." or href="callto:..."
      B. Phone-related attributes or CSS classes on the tag or any ancestor
      C. Phone keyword in surrounding text within the parent element
    """
    if tag is None:
        return False

    # A: explicit tel/callto link
    if tag.name == "a":
        href = tag.get("href", "")
        if href.startswith("tel:") or href.startswith("callto:"):
            return True

    # B: walk up the DOM tree checking attributes and classes
    for ancestor in [tag, *tag.parents]:
        if not hasattr(ancestor, "attrs"):
            continue
        for attr in PHONE_ATTRS:
            val = ancestor.get(attr, "")
            if isinstance(val, list):
                val = " ".join(val)
            if CONTEXT_KEYWORD_RE.search(str(val)):
                return True
        classes = " ".join(ancestor.get("class", []))
        if CONTEXT_KEYWORD_RE.search(classes):
            return True

    # C: keyword in a 60-char window around the number inside the parent text
    parent_text = tag.parent.get_text() if tag.parent else ""
    index = parent_text.find(raw)
    if index != -1:
        window = parent_text[max(0, index - 60): index + len(raw) + 60]
        if CONTEXT_KEYWORD_RE.search(window):
            return True

    return False


def validate_with_libphonenumber(raw: str, region: str = DEFAULT_REGION):
    """
    Layer 5: validate against Google's libphonenumber.
    Returns a PhoneNumber object if valid, None otherwise.
    """
    try:
        parsed = phonenumbers.parse(raw, region)
        if is_valid_number(parsed):
            return parsed
    except phonenumbers.NumberParseException:
        pass
    return None


def normalize_phone(parsed) -> str:
    """Format a PhoneNumber object as E.164 (+573001234567)."""
    return phonenumbers.format_number(parsed, PhoneNumberFormat.E164)


def extract_from_html(html: str, url: str = "") -> set:
    """
    Run two complementary detection strategies against a raw HTML string.

    Strategy A — PhoneNumberMatcher:
        Runs Google's libphonenumber matcher over the page's visible text.
        High precision; understands linguistic context around numbers.

    Strategy B — Regex + 5-layer pipeline:
        Scans raw HTML (including attributes) with PHONE_REGEX, then applies
        basic checks, blacklist, HTML context, and libphonenumber validation.
        Catches numbers inside href="tel:..." and data-* attributes that
        PhoneNumberMatcher would miss because it only sees plain text.
    """
    results = set()
    soup = BeautifulSoup(html, "html.parser")

    text_content = soup.get_text(separator=" ")
    for match in PhoneNumberMatcher(text_content, DEFAULT_REGION):
        if is_valid_number(match.number):
            e164 = phonenumbers.format_number(match.number, PhoneNumberFormat.E164)
            results.add(e164)

    for match in PHONE_REGEX.finditer(html):
        raw = match.group(0).strip()

        if not passes_basic_checks(raw):
            continue
        if not passes_blacklist(raw):
            continue

        # Locate the corresponding BeautifulSoup tag for HTML context checks
        tag = soup.find(string=re.compile(re.escape(raw[:10])))
        if tag:
            tag = tag.parent

        if not has_html_context(tag, soup, raw):
            continue

        parsed = validate_with_libphonenumber(raw)
        if parsed:
            results.add(normalize_phone(parsed))

    return results


def extract_phones(domain: str, subdomains: list = None) -> list:
    """
    Extract valid phone numbers from a domain and its subdomains.

    Crawls COMMON_PATHS on each target over https then http, parses each
    HTML response through the 5-layer pipeline, and returns a deduplicated
    sorted list of E.164-formatted phone numbers.

    Args:
        domain: Base domain (e.g. "example.com")
        subdomains: Optional list of subdomain strings

    Returns:
        Sorted list of phone numbers in E.164 format
    """
    phones: set = set()
    visited: set = set()

    targets = {domain}
    if subdomains:
        targets.update(subdomains)

    for target in targets:
        for scheme in ["https", "http"]:
            base = f"{scheme}://{target}"
            for path in COMMON_PATHS:
                url = f"{base}{path}"
                if url in visited:
                    continue
                visited.add(url)

                try:
                    response = requests.get(url, headers=HEADERS, timeout=8)
                    response.raise_for_status()

                    content_type = response.headers.get("Content-Type", "").lower()
                    if "text/html" not in content_type:
                        continue

                    found = extract_from_html(response.text, url)
                    phones.update(found)

                except requests.RequestException:
                    continue

    return sorted(phones)