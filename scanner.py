from __future__ import annotations

from datetime import datetime, timezone
from time import perf_counter
from urllib.parse import urlparse
import requests

SECURITY_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "purpose": "Tells browsers to use HTTPS for future requests.",
        "recommendation": "Enable HSTS on HTTPS sites after confirming HTTPS works throughout the site. Choose max-age and includeSubDomains carefully.",
    },
    {
        "name": "Content-Security-Policy",
        "purpose": "Helps restrict the sources from which a page can load content.",
        "recommendation": "Define a Content-Security-Policy suited to the application. Start with report-only mode when tuning a policy.",
    },
    {
        "name": "X-Content-Type-Options",
        "purpose": "Helps prevent MIME-type sniffing.",
        "recommendation": "Set X-Content-Type-Options: nosniff.",
    },
    {
        "name": "X-Frame-Options",
        "purpose": "Provides a legacy control against unwanted framing.",
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN as appropriate; a CSP frame-ancestors directive is the modern control.",
    },
    {
        "name": "Referrer-Policy",
        "purpose": "Controls how much referrer information browsers send.",
        "recommendation": "Choose a suitable policy such as strict-origin-when-cross-origin.",
    },
]

def normalize_url(value: str) -> str:
    """Validate and normalize a web URL without accepting local or non-HTTP schemes."""
    value = value.strip()
    if not value:
        raise ValueError("Enter a website URL.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise ValueError("That URL does not contain a valid hostname.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded usernames or passwords are not supported.")
    if any(ch.isspace() for ch in parsed.netloc):
        raise ValueError("The URL contains invalid whitespace.")
    return value

def scan_url(url: str, timeout: int = 10, verify_tls: bool = True) -> dict:
    """Make one GET request and evaluate common security headers."""
    try:
        normalized = normalize_url(url)
    except ValueError as exc:
        return {"error": str(exc)}

    started = perf_counter()
    try:
        response = requests.get(
            normalized,
            timeout=max(1, min(int(timeout), 30)),
            verify=verify_tls,
            allow_redirects=True,
            headers={"User-Agent": "AutomatedWebScanner/1.0 (educational security-header check)"},
        )
        elapsed_ms = round((perf_counter() - started) * 1000)
        header_map = {key.lower(): value for key, value in response.headers.items()}
        checks = []
        for item in SECURITY_HEADERS:
            value = header_map.get(item["name"].lower(), "")
            checks.append({
                **item,
                "present": bool(value.strip()),
                "value": value.strip(),
            })
        scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines = [
            "AUTOMATED WEB SCANNER REPORT",
            "=" * 32,
            f"Requested URL: {normalized}",
            f"Final URL: {response.url}",
            f"Scanned at: {scanned_at}",
            f"HTTP status: {response.status_code}",
            f"Response time: {elapsed_ms} ms",
            "",
            "SECURITY HEADER CHECKS",
            "-" * 32,
        ]
        for item in checks:
            status = "PRESENT" if item["present"] else "MISSING"
            lines.append(f"{item['name']}: {status}")
            lines.append(f"  Value: {item['value'] or '—'}")
            lines.append(f"  Purpose: {item['purpose']}")
            if not item["present"]:
                lines.append(f"  Recommendation: {item['recommendation']}")
        lines.extend([
            "",
            "LIMITATION: This is a basic response-header check, not a penetration test or proof of vulnerability.",
            "Only scan websites you own or are authorized to assess.",
        ])
        return {
            "url": normalized,
            "final_url": response.url,
            "status_code": response.status_code,
            "elapsed_ms": elapsed_ms,
            "headers": checks,
            "report": "\n".join(lines),
            "scanned_at": scanned_at,
        }
    except requests.exceptions.SSLError:
        return {"error": "TLS certificate verification failed. Confirm the URL and certificate. You may disable verification only for a controlled test."}
    except requests.exceptions.Timeout:
        return {"error": "The website did not respond before the timeout. Try a longer timeout or check the URL."}
    except requests.exceptions.TooManyRedirects:
        return {"error": "The website redirected too many times."}
    except requests.exceptions.ConnectionError:
        return {"error": "Could not connect to the website. Check the URL and whether the site is reachable."}
    except requests.exceptions.RequestException as exc:
        return {"error": f"Request failed: {exc.__class__.__name__}."}

def save_report(report: str, path: str = "web_scan_report.txt") -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(report)
    return path
