"""
Pydantic models for security analysis results.

Provides schemas for the Security Analysis Engine output,
including individual findings, severity categories, and
overall security grading.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SecurityFinding(BaseModel):
    """A single security finding from the analysis."""

    category: str = Field(
        ...,
        description="Finding category: 'header', 'cookie', 'ssl', 'info'.",
    )
    severity: str = Field(
        ...,
        description="Severity level: 'critical', 'high', 'medium', 'low', 'info'.",
    )
    title: str = Field(
        ...,
        description="Short descriptive title of the finding.",
    )
    description: str = Field(
        ...,
        description="Detailed explanation of the security issue.",
    )
    recommendation: str = Field(
        ...,
        description="Actionable recommendation to fix the issue.",
    )


class SecurityReport(BaseModel):
    """Complete security analysis report for a URL."""

    url: str = Field(..., description="The analyzed URL.")
    grade: str = Field(
        ...,
        description="Overall security grade from A+ to F.",
    )
    score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Numerical security score (0–100).",
    )
    findings: list[SecurityFinding] = Field(
        default_factory=list,
        description="List of individual security findings.",
    )
    summary: dict[str, int] = Field(
        default_factory=dict,
        description="Count of findings by severity level.",
    )
    technologies: list[str] = Field(
        default_factory=list,
        description="Detected technologies from response headers.",
    )
    ssl_info: dict[str, Any] | None = Field(
        None,
        description="SSL/TLS certificate details (if HTTPS).",
    )
    analyzed_at: datetime = Field(
        ...,
        description="Timestamp of the analysis.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "url": "https://example.com",
                    "grade": "C",
                    "score": 55,
                    "findings": [
                        {
                            "category": "header",
                            "severity": "high",
                            "title": "Missing Content-Security-Policy",
                            "description": "No CSP header detected.",
                            "recommendation": "Add a Content-Security-Policy header.",
                        }
                    ],
                    "summary": {"critical": 0, "high": 1, "medium": 2, "low": 1, "info": 1},
                    "technologies": ["cloudflare"],
                    "ssl_info": {"issuer": "DigiCert", "expires": "2027-01-01"},
                    "analyzed_at": "2026-03-05T12:00:00Z",
                }
            ]
        }
    }


class AnalyzeRequest(BaseModel):
    """Request body for POST /analyze endpoint."""

    url: str = Field(
        ...,
        description="The URL to analyze. Must start with http:// or https://.",
        examples=["https://example.com"],
    )
