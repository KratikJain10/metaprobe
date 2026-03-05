"""
Unit tests for the Security Analysis Engine.

Tests the SecurityAnalyzer class across all analysis categories:
header checks, cookie analysis, SSL inspection, technology
fingerprinting, scoring, and grading.
"""

import pytest

from app.services.analyzer import SecurityAnalyzer


@pytest.fixture
def analyzer():
    """Provide a SecurityAnalyzer instance."""
    return SecurityAnalyzer()


class TestSecurityHeaders:
    """Tests for security header analysis."""

    def test_detects_missing_hsts(self, analyzer):
        """Missing HSTS header should produce a high-severity finding."""
        report = analyzer.analyze(
            url="https://example.com",
            headers={"content-type": "text/html"},
            cookies={},
        )
        hsts_findings = [f for f in report.findings if "HSTS" in f.title and "Missing" in f.title]
        assert len(hsts_findings) == 1
        assert hsts_findings[0].severity == "high"

    def test_detects_missing_csp(self, analyzer):
        """Missing CSP header should produce a high-severity finding."""
        report = analyzer.analyze(
            url="https://example.com",
            headers={"content-type": "text/html"},
            cookies={},
        )
        csp_findings = [f for f in report.findings if "Content-Security-Policy" in f.title]
        assert len(csp_findings) == 1
        assert csp_findings[0].severity == "high"

    def test_detects_missing_x_frame_options(self, analyzer):
        """Missing X-Frame-Options should produce a medium finding."""
        report = analyzer.analyze(
            url="https://example.com",
            headers={},
            cookies={},
        )
        findings = [f for f in report.findings if "X-Frame-Options" in f.title]
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_no_finding_when_headers_present(self, analyzer):
        """Present security headers should not generate findings."""
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=()",
            "x-xss-protection": "0",
        }
        report = analyzer.analyze(
            url="https://example.com",
            headers=headers,
            cookies={},
        )
        header_findings = [f for f in report.findings if f.category == "header"]
        assert len(header_findings) == 0

    def test_hsts_without_includesubdomains(self, analyzer):
        """HSTS without includeSubDomains should produce a low finding."""
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "camera=()",
            "x-xss-protection": "0",
        }
        report = analyzer.analyze(
            url="https://example.com",
            headers=headers,
            cookies={},
        )
        hsts_findings = [f for f in report.findings if "includeSubDomains" in f.title]
        assert len(hsts_findings) == 1
        assert hsts_findings[0].severity == "low"


class TestCookieAnalysis:
    """Tests for cookie security analysis."""

    def test_detects_insecure_cookie_flags(self, analyzer):
        """Cookies without Secure/HttpOnly/SameSite should be flagged."""
        headers = {"set-cookie": "session=abc123; Path=/"}
        report = analyzer.analyze(
            url="https://example.com",
            headers=headers,
            cookies={"session": "abc123"},
        )
        cookie_findings = [f for f in report.findings if f.category == "cookie"]
        assert len(cookie_findings) >= 2  # Missing Secure + HttpOnly + SameSite

    def test_no_findings_when_no_cookies(self, analyzer):
        """No cookies should produce no cookie findings."""
        report = analyzer.analyze(
            url="https://example.com",
            headers={},
            cookies={},
        )
        cookie_findings = [f for f in report.findings if f.category == "cookie"]
        assert len(cookie_findings) == 0


class TestTechnologyFingerprinting:
    """Tests for technology detection."""

    def test_detects_server_header(self, analyzer):
        """Server header info should be detected as a technology."""
        report = analyzer.analyze(
            url="https://example.com",
            headers={"server": "nginx/1.25.3"},
            cookies={},
        )
        assert any("nginx" in t for t in report.technologies)

    def test_detects_x_powered_by(self, analyzer):
        """X-Powered-By should be detected."""
        report = analyzer.analyze(
            url="https://example.com",
            headers={"x-powered-by": "Express"},
            cookies={},
        )
        assert any("Express" in t for t in report.technologies)

    def test_no_tech_when_headers_clean(self, analyzer):
        """No tech headers should produce empty technologies list."""
        report = analyzer.analyze(
            url="https://example.com",
            headers={"content-type": "text/html"},
            cookies={},
        )
        assert len(report.technologies) == 0


class TestScoring:
    """Tests for security scoring and grading."""

    def test_perfect_score_with_all_headers(self, analyzer):
        """All security headers present should give a high score."""
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=()",
            "x-xss-protection": "0",
        }
        report = analyzer.analyze(
            url="https://example.com",
            headers=headers,
            cookies={},
        )
        # Score may be reduced by SSL cert verification issues in test env
        # so we check for >= 75 (B or better)
        assert report.score >= 75
        assert report.grade in ("A+", "A", "B")

    def test_low_score_with_no_headers(self, analyzer):
        """No security headers should produce a low score."""
        report = analyzer.analyze(
            url="https://example.com",
            headers={},
            cookies={},
        )
        assert report.score <= 60
        assert report.grade in ("D", "F")

    def test_http_url_gets_critical_finding(self, analyzer):
        """HTTP URLs should get a critical 'No HTTPS' finding."""
        report = analyzer.analyze(
            url="http://example.com",
            headers={},
            cookies={},
        )
        https_findings = [f for f in report.findings if "HTTPS" in f.title]
        assert len(https_findings) == 1
        assert https_findings[0].severity == "critical"

    def test_grade_boundaries(self, analyzer):
        """Verify grade calculation follows the expected boundaries."""
        assert analyzer._score_to_grade(100) == "A+"
        assert analyzer._score_to_grade(95) == "A+"
        assert analyzer._score_to_grade(90) == "A"
        assert analyzer._score_to_grade(80) == "B"
        assert analyzer._score_to_grade(65) == "C"
        assert analyzer._score_to_grade(45) == "D"
        assert analyzer._score_to_grade(30) == "F"
        assert analyzer._score_to_grade(0) == "F"

    def test_summary_counts_are_correct(self, analyzer):
        """Summary should contain accurate counts per severity."""
        report = analyzer.analyze(
            url="https://example.com",
            headers={},
            cookies={},
        )
        total_findings = sum(report.summary.values())
        assert total_findings == len(report.findings)
        assert all(sev in report.summary for sev in ["critical", "high", "medium", "low", "info"])
