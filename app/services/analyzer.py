"""
Security Analysis Engine.

Inspects HTTP metadata (headers, cookies, SSL certificates) and produces
a comprehensive security report with findings, severity scoring, and
an overall A+ through F grade.

Analysis Categories:
- Security Headers: CSP, HSTS, X-Frame-Options, etc.
- Cookie Security: Secure, HttpOnly, SameSite flags
- SSL/TLS: Certificate validity, expiry, issuer
- Technology Fingerprinting: Server software detection
"""

import logging
import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urlparse

from app.models.analysis import SecurityFinding, SecurityReport

logger = logging.getLogger(__name__)

# Severity weights for scoring
SEVERITY_WEIGHTS = {
    "critical": 20,
    "high": 12,
    "medium": 6,
    "low": 2,
    "info": 0,
}

# Security headers to check — (header_name, severity_if_missing, title, description, recommendation)
SECURITY_HEADERS = [
    (
        "strict-transport-security",
        "high",
        "Missing Strict-Transport-Security (HSTS)",
        "The server does not enforce HTTPS via HSTS. Browsers may connect over insecure HTTP, making users vulnerable to downgrade attacks and cookie hijacking.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
    ),
    (
        "content-security-policy",
        "high",
        "Missing Content-Security-Policy (CSP)",
        "No Content-Security-Policy header detected. Without CSP, the site is more vulnerable to cross-site scripting (XSS) and data injection attacks.",
        "Implement a Content-Security-Policy header. Start with a report-only policy and tighten gradually.",
    ),
    (
        "x-frame-options",
        "medium",
        "Missing X-Frame-Options",
        "The X-Frame-Options header is not set. The page may be vulnerable to clickjacking attacks where an attacker frames your page.",
        "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header.",
    ),
    (
        "x-content-type-options",
        "medium",
        "Missing X-Content-Type-Options",
        "Without 'X-Content-Type-Options: nosniff', browsers may MIME-sniff responses, potentially executing malicious content.",
        "Add 'X-Content-Type-Options: nosniff' header to all responses.",
    ),
    (
        "referrer-policy",
        "low",
        "Missing Referrer-Policy",
        "No Referrer-Policy header detected. The browser may leak URL information to third-party sites via the Referer header.",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
    ),
    (
        "permissions-policy",
        "low",
        "Missing Permissions-Policy",
        "No Permissions-Policy (formerly Feature-Policy) header detected. Browser features like camera, microphone, and geolocation are unrestricted.",
        "Add a Permissions-Policy header to restrict unnecessary browser features.",
    ),
    (
        "x-xss-protection",
        "info",
        "Missing X-XSS-Protection",
        "The legacy X-XSS-Protection header is not set. While modern browsers rely on CSP, this header provides defense-in-depth for older browsers.",
        "Add 'X-XSS-Protection: 0' (to avoid false positives) or rely on a strong CSP instead.",
    ),
]

# Technology fingerprinting headers
TECH_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-varnish",
    "x-cdn",
    "via",
]


class SecurityAnalyzer:
    """
    Analyzes HTTP metadata for security issues.

    Produces a SecurityReport with categorized findings,
    a numerical score (0–100), and a letter grade (A+ to F).
    """

    def analyze(
        self,
        url: str,
        headers: dict[str, str],
        cookies: dict[str, str],
    ) -> SecurityReport:
        """
        Run the full security analysis suite.

        Args:
            url: The target URL.
            headers: HTTP response headers (lowercase keys).
            cookies: Extracted cookies.

        Returns:
            A SecurityReport with findings and grading.
        """
        findings: list[SecurityFinding] = []

        # Normalize header keys to lowercase
        lower_headers = {k.lower(): v for k, v in headers.items()}

        # 1. Check security headers
        findings.extend(self._check_security_headers(lower_headers))

        # 2. Check cookie security
        findings.extend(self._check_cookies(cookies, lower_headers))

        # 3. Technology fingerprinting
        technologies = self._detect_technologies(lower_headers)
        if technologies:
            findings.append(SecurityFinding(
                category="info",
                severity="info",
                title="Technology Information Disclosure",
                description=(
                    f"The following technologies were detected from response headers: "
                    f"{', '.join(technologies)}. This information can help attackers "
                    f"identify known vulnerabilities."
                ),
                recommendation=(
                    "Consider removing or masking technology-revealing headers "
                    "like 'Server' and 'X-Powered-By' in production."
                ),
            ))

        # 4. SSL/TLS analysis
        ssl_info = self._check_ssl(url)
        if ssl_info and ssl_info.get("error"):
            findings.append(SecurityFinding(
                category="ssl",
                severity="critical",
                title="SSL/TLS Certificate Issue",
                description=f"SSL certificate error: {ssl_info['error']}",
                recommendation="Ensure a valid SSL/TLS certificate is installed and not expired.",
            ))
        elif ssl_info and ssl_info.get("days_until_expiry") is not None:
            days = ssl_info["days_until_expiry"]
            if days < 0:
                findings.append(SecurityFinding(
                    category="ssl",
                    severity="critical",
                    title="SSL Certificate Expired",
                    description=f"The SSL certificate expired {abs(days)} days ago.",
                    recommendation="Renew the SSL certificate immediately.",
                ))
            elif days < 30:
                findings.append(SecurityFinding(
                    category="ssl",
                    severity="high",
                    title="SSL Certificate Expiring Soon",
                    description=f"The SSL certificate expires in {days} days.",
                    recommendation="Renew the SSL certificate before expiry to avoid service disruption.",
                ))

        # Check for HTTPS
        parsed = urlparse(url)
        if parsed.scheme != "https":
            findings.append(SecurityFinding(
                category="ssl",
                severity="critical",
                title="No HTTPS",
                description="The URL does not use HTTPS. All traffic is transmitted in plaintext.",
                recommendation="Migrate to HTTPS with a valid TLS certificate.",
            ))

        # Calculate score and grade
        score = self._calculate_score(findings)
        grade = self._score_to_grade(score)
        summary = self._summarize_findings(findings)

        return SecurityReport(
            url=url,
            grade=grade,
            score=score,
            findings=findings,
            summary=summary,
            technologies=technologies,
            ssl_info=ssl_info,
            analyzed_at=datetime.now(UTC),
        )

    def _check_security_headers(
        self, headers: dict[str, str]
    ) -> list[SecurityFinding]:
        """Check for missing or misconfigured security headers."""
        findings = []

        for header_name, severity, title, description, recommendation in SECURITY_HEADERS:
            if header_name not in headers:
                findings.append(SecurityFinding(
                    category="header",
                    severity=severity,
                    title=title,
                    description=description,
                    recommendation=recommendation,
                ))

        # Check for insecure HSTS configuration
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            if "includesubdomains" not in hsts.lower():
                findings.append(SecurityFinding(
                    category="header",
                    severity="low",
                    title="HSTS Missing includeSubDomains",
                    description="The HSTS header does not include the includeSubDomains directive.",
                    recommendation="Add 'includeSubDomains' to the HSTS header for complete coverage.",
                ))

        return findings

    def _check_cookies(
        self, cookies: dict[str, str], headers: dict[str, str]
    ) -> list[SecurityFinding]:
        """Analyze cookies for security flag compliance."""
        findings = []

        # Parse Set-Cookie headers for flag analysis
        set_cookie_headers = []
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                set_cookie_headers.append(value)

        if not cookies and not set_cookie_headers:
            return findings  # No cookies to analyze

        for name in cookies:
            # Check each cookie's flags from raw Set-Cookie header
            cookie_header = ""
            for sc in set_cookie_headers:
                if sc.startswith(f"{name}="):
                    cookie_header = sc.lower()
                    break

            if not cookie_header:
                # If we can't find the raw header, flag as potentially insecure
                continue

            if "secure" not in cookie_header:
                findings.append(SecurityFinding(
                    category="cookie",
                    severity="high",
                    title=f"Cookie '{name}' Missing Secure Flag",
                    description=(
                        f"The cookie '{name}' is not marked as Secure. "
                        f"It may be transmitted over unencrypted HTTP connections."
                    ),
                    recommendation=f"Add the 'Secure' flag to the '{name}' cookie.",
                ))

            if "httponly" not in cookie_header:
                findings.append(SecurityFinding(
                    category="cookie",
                    severity="medium",
                    title=f"Cookie '{name}' Missing HttpOnly Flag",
                    description=(
                        f"The cookie '{name}' is not marked as HttpOnly. "
                        f"JavaScript can access this cookie, increasing XSS risk."
                    ),
                    recommendation=f"Add the 'HttpOnly' flag to the '{name}' cookie.",
                ))

            if "samesite" not in cookie_header:
                findings.append(SecurityFinding(
                    category="cookie",
                    severity="medium",
                    title=f"Cookie '{name}' Missing SameSite Attribute",
                    description=(
                        f"The cookie '{name}' does not have a SameSite attribute. "
                        f"It may be sent in cross-site requests (CSRF risk)."
                    ),
                    recommendation=f"Add 'SameSite=Lax' or 'SameSite=Strict' to the '{name}' cookie.",
                ))

        return findings

    def _detect_technologies(self, headers: dict[str, str]) -> list[str]:
        """Extract technology information from response headers."""
        technologies = []

        for header in TECH_HEADERS:
            value = headers.get(header)
            if value:
                technologies.append(f"{header}: {value}")

        return technologies

    def _check_ssl(self, url: str) -> dict | None:
        """
        Check SSL/TLS certificate details for HTTPS URLs.

        Returns certificate info dict or None for non-HTTPS URLs.
        """
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return None

        hostname = parsed.hostname
        port = parsed.port or 443

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            if not cert:
                return {"error": "No certificate returned"}

            # Parse expiry
            not_after = cert.get("notAfter", "")
            not_before = cert.get("notBefore", "")

            # Parse issuer
            issuer_parts = cert.get("issuer", ())
            issuer = ""
            for part in issuer_parts:
                for key, value in part:
                    if key == "organizationName":
                        issuer = value
                        break

            # Calculate days until expiry
            try:
                expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry_date = expiry_date.replace(tzinfo=UTC)
                days_until_expiry = (expiry_date - datetime.now(UTC)).days
            except (ValueError, TypeError):
                days_until_expiry = None

            # Subject
            subject_parts = cert.get("subject", ())
            subject = ""
            for part in subject_parts:
                for key, value in part:
                    if key == "commonName":
                        subject = value
                        break

            return {
                "subject": subject,
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
                "days_until_expiry": days_until_expiry,
                "serial_number": cert.get("serialNumber", ""),
                "version": cert.get("version", ""),
            }

        except ssl.SSLCertVerificationError as exc:
            return {"error": f"Certificate verification failed: {exc}"}
        except TimeoutError:
            return {"error": "Connection timed out during SSL handshake"}
        except Exception as exc:
            logger.warning("SSL check failed for %s: %s", url, exc)
            return {"error": str(exc)}

    def _calculate_score(self, findings: list[SecurityFinding]) -> int:
        """
        Calculate a security score from 0–100 based on findings.

        Starts at 100 and deducts points per finding based on severity.
        """
        score = 100
        for finding in findings:
            weight = SEVERITY_WEIGHTS.get(finding.severity, 0)
            score -= weight
        return max(0, min(100, score))

    def _score_to_grade(self, score: int) -> str:
        """Convert a numerical score to a letter grade."""
        if score >= 95:
            return "A+"
        elif score >= 85:
            return "A"
        elif score >= 75:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 40:
            return "D"
        else:
            return "F"

    def _summarize_findings(
        self, findings: list[SecurityFinding]
    ) -> dict[str, int]:
        """Count findings by severity level."""
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for finding in findings:
            if finding.severity in summary:
                summary[finding.severity] += 1
        return summary
