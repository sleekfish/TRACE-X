"""Enumerated string constants used across models (stored as plain strings)."""


class UserRole:
    ADMIN = "admin"
    INVESTIGATOR = "investigator"
    ANALYST = "analyst"
    VIEWER = "viewer"

    ALL = [ADMIN, INVESTIGATOR, ANALYST, VIEWER]


class CaseStatus:
    OPEN = "open"
    ACTIVE = "active"
    UNDER_REVIEW = "under_review"
    CLOSED = "closed"
    ARCHIVED = "archived"

    ALL = [OPEN, ACTIVE, UNDER_REVIEW, CLOSED, ARCHIVED]


class Severity:
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    ALL = [INFO, LOW, MEDIUM, HIGH, CRITICAL]


class AnalysisStatus:
    PENDING = "PENDING"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    SKIPPED = "SKIPPED"

    ALL = [PENDING, QUEUED, RUNNING, COMPLETED, FAILED, PARTIAL, UNAVAILABLE, SKIPPED]


class IntegrationStatus:
    AVAILABLE = "AVAILABLE"
    NOT_INSTALLED = "NOT_INSTALLED"
    CONFIGURATION_REQUIRED = "CONFIGURATION_REQUIRED"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"


class FindingStatus:
    OPEN = "open"
    REQUIRES_REVIEW = "requires_review"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"
    CLOSED = "closed"

    ALL = [OPEN, REQUIRES_REVIEW, CONFIRMED, DISMISSED, CLOSED]


class RelationshipType:
    SHARED_INDICATOR = "SHARED_INDICATOR"
    SAME_IP = "SAME_IP"
    SAME_DOMAIN = "SAME_DOMAIN"
    SAME_URL = "SAME_URL"
    SAME_HASH = "SAME_HASH"
    SAME_HOSTNAME = "SAME_HOSTNAME"
    SAME_EMAIL = "SAME_EMAIL"
    SAME_CERTIFICATE = "SAME_CERTIFICATE"
    HISTORICAL_CORRELATION = "HISTORICAL_CORRELATION"
    CASE_EVIDENCE = "CASE_EVIDENCE"
    EVIDENCE_EVENT = "EVIDENCE_EVENT"
    EVENT_INDICATOR = "EVENT_INDICATOR"
    CASE_INDICATOR = "CASE_INDICATOR"
    FINDING_EVIDENCE = "FINDING_EVIDENCE"


class AnalysisSource:
    """Explicitly distinguishes REAL forensic output from DEMO/MOCK data."""

    REAL = "REAL"
    DEMO = "DEMO"
    MOCK = "MOCK"
    SIMULATED = "SIMULATED"

    ALL = [REAL, DEMO, MOCK, SIMULATED]