"""Small local web server and heuristic URL phishing detector."""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
}
SUSPICIOUS_TERMS = {
    "account", "auth", "billing", "confirm", "login", "log-in",
    "password", "recover", "secure", "signin", "support", "update", "verify",
}
BRANDS = {
    "paypal", "apple", "amazon", "microsoft", "google", "facebook",
    "instagram", "netflix", "bankofamerica", "chase", "coinbase",
}


def analyze_url(raw_url: str) -> dict:
    """Return a transparent, explainable heuristic assessment of a URL."""
    value = raw_url.strip()
    if not value:
        raise ValueError("Enter a URL to analyze.")
    candidate = value if "://" in value else "https://" + value
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower().rstrip(".")
        # Accessing .port also validates malformed port syntax.
        _ = parts.port
    except ValueError as exc:
        raise ValueError("That URL is not formatted correctly.") from exc
    if not host or any(ch.isspace() for ch in host):
        raise ValueError("Enter a valid domain or URL, such as example.com.")

    score = 0
    findings: list[dict] = []

    def flag(points: int, title: str, detail: str) -> None:
        nonlocal score
        score += points
        findings.append({"title": title, "detail": detail, "points": points})

    if parts.scheme.lower() not in {"http", "https"}:
        flag(25, "Unusual link protocol", f"The link uses {parts.scheme or 'an unknown'} protocol.")
    elif parts.scheme.lower() == "http":
        flag(12, "No HTTPS encryption", "The connection does not use HTTPS.")

    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        flag(24, "IP address used as host", "The link points directly to an IP address instead of a recognizable domain.")
    if "@" in parts.netloc:
        flag(25, "Misleading @ sign", "Text before @ can disguise the actual destination host.")
    if host.startswith("xn--") or ".xn--" in host:
        flag(18, "Internationalized domain", "Punycode can be used to make lookalike domains harder to spot.")
    if host in SHORTENERS:
        flag(18, "Shortened link", "The final destination is hidden behind a URL shortener.")
    if len(host) > 35:
        flag(10, "Long domain name", "Long hostnames are harder to inspect and can conceal misleading words.")
    if host.count("-") >= 2:
        flag(8, "Many hyphens in domain", "The hostname contains several hyphens, a pattern sometimes used in deceptive domains.")
    labels = host.split(".")
    if len(labels) >= 5:
        flag(8, "Many subdomains", "Several subdomains can make the real registered domain less obvious.")

    words = set(re.findall(r"[a-z0-9]+", (host + " " + parts.path + " " + parts.query).lower()))
    risky = sorted(words & SUSPICIOUS_TERMS)
    if risky:
        flag(min(18, 6 + 4 * len(risky)), "Sensitive-action wording", "The URL contains: " + ", ".join(risky) + ".")
    host_compact = "".join(labels[:-1])
    brand_hits = [brand for brand in BRANDS if brand in host_compact]
    if brand_hits:
        # A brand term inside an unrelated hostname is a warning, not proof.
        exact_or_subdomain = any(host == brand + suffix or host.endswith("." + brand + suffix)
                                 for brand in brand_hits for suffix in (".com", ".net", ".org"))
        if not exact_or_subdomain:
            flag(20, "Brand name in hostname", "A well-known brand appears inside the hostname; check that the domain is its official one.")
    if len(value) > 180:
        flag(8, "Unusually long URL", "Long URLs can hide unexpected destinations or tracking parameters.")
    if parts.password is not None or parts.username is not None:
        flag(20, "Embedded credentials", "The URL includes user information before the host.")

    score = min(score, 100)
    if score >= 50:
        level, label = "high", "High risk"
    elif score >= 25:
        level, label = "medium", "Suspicious"
    else:
        level, label = "low", "Lower risk"
    if not findings:
        findings.append({"title": "No common warning signs found", "detail": "This URL passed basic format checks. That does not guarantee the site is safe.", "points": 0})
    return {
        "url": value,
        "host": host,
        "score": score,
        "level": level,
        "label": label,
        "findings": findings,
        "checked": "URL structure and wording only",
        "disclaimer": "This local heuristic is not a reputation service. It does not open the link, inspect page content, or guarantee safety.",
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, content: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        names = {"/": ("index.html", "text/html; charset=utf-8"),
                 "/styles.css": ("styles.css", "text/css; charset=utf-8"),
                 "/app.js": ("app.js", "text/javascript; charset=utf-8")}
        if path not in names:
            self._send(404, b"Not found", "text/plain; charset=utf-8")
            return
        name, mime = names[path]
        self._send(200, (STATIC / name).read_bytes(), mime)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/analyze":
            self._send(404, b'{"error":"Not found"}', "application/json; charset=utf-8")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 10_000:
                raise ValueError("Request is too large.")
            payload = json.loads(self.rfile.read(length))
            result = analyze_url(str(payload.get("url", "")))
            body = json.dumps(result).encode("utf-8")
            self._send(200, body, "application/json; charset=utf-8")
        except (ValueError, json.JSONDecodeError) as exc:
            body = json.dumps({"error": str(exc)}).encode("utf-8")
            self._send(400, body, "application/json; charset=utf-8")

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {fmt % args}")


if __name__ == "__main__":
    address = ("127.0.0.1", 8000)
    print(f"PhishGuard running at http://{address[0]}:{address[1]}")
    ThreadingHTTPServer(address, Handler).serve_forever()

