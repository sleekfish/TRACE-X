"""Pydantic v2 request/response schemas for the TRACE-X MEMORY API."""

from app.schemas.activity import ActivityOut, ActivityPage
from app.schemas.ai import AI_DISCLAIMER, ExplainRequest, ExplainResponse
from app.schemas.analysis import (
    AnalysisJobDetail,
    AnalysisJobOut,
    AnalysisJobPage,
    AnalysisRequest,
    AnalysisRunResponse,
    AnalysisSkip,
    ToolInfo,
)
from app.schemas.auth import (
    LoginRequest,
    Token,
    TokenPayload,
    UserCreate,
    UserList,
    UserOut,
    UserRegister,
    UserUpdate,
)
from app.schemas.case import (
    CaseCreate,
    CaseDetail,
    CaseList,
    CaseOut,
    CasePage,
    CaseStats,
    CaseSummary,
    CaseUpdate,
)
from app.schemas.common import (
    APIModel,
    ErrorDetail,
    ErrorResponse,
    Message,
    ORMModel,
    Page,
    UTCDateTime,
)
from app.schemas.dashboard import DashboardSummary, DashboardTotals, SeverityCount
from app.schemas.evidence import (
    EvidenceDetail,
    EvidenceIntegrity,
    EvidenceOut,
    EvidencePage,
    EvidenceUpdate,
)
from app.schemas.event import (
    EventCreate,
    EventOut,
    EventPage,
    EventSourceCount,
    EventStatistics,
    EventTypeCount,
)
from app.schemas.finding import FindingCreate, FindingOut, FindingPage, FindingUpdate
from app.schemas.indicator import (
    IndicatorCreate,
    IndicatorDetail,
    IndicatorOut,
    IndicatorPage,
    IndicatorStatistics,
    IndicatorTypeCount,
)
from app.schemas.integration import IntegrationCheckResult, IntegrationStatusOut
from app.schemas.memory import (
    MemoryCaseSummary,
    MemoryMatch,
    MemoryOverview,
    MemorySearchRequest,
    MemorySearchResponse,
)
from app.schemas.relationship import (
    GraphEdge,
    GraphNode,
    GraphQuery,
    GraphResponse,
    RelationshipOut,
    RelationshipPage,
)
from app.schemas.report import ReportFileInfo, ReportOut, ReportRequest
from app.schemas.search import (
    SearchHit,
    SearchRequest,
    SearchResponse,
    SearchTypeCount,
)
from app.schemas.timeline import (
    TimelineBucket,
    TimelineEntry,
    TimelineGap,
    TimelineHistogram,
    TimelineResponse,
)

__all__ = [
    # common
    "APIModel",
    "ORMModel",
    "Page",
    "Message",
    "ErrorDetail",
    "ErrorResponse",
    "UTCDateTime",
    # auth
    "UserCreate",
    "UserRegister",
    "UserUpdate",
    "UserOut",
    "UserList",
    "LoginRequest",
    "Token",
    "TokenPayload",
    # case
    "CaseCreate",
    "CaseUpdate",
    "CaseSummary",
    "CaseOut",
    "CaseDetail",
    "CaseStats",
    "CasePage",
    "CaseList",
    # evidence
    "EvidenceUpdate",
    "EvidenceOut",
    "EvidenceDetail",
    "EvidenceIntegrity",
    "EvidencePage",
    # event
    "EventOut",
    "EventCreate",
    "EventPage",
    "EventStatistics",
    "EventSourceCount",
    "EventTypeCount",
    # indicator
    "IndicatorOut",
    "IndicatorCreate",
    "IndicatorDetail",
    "IndicatorPage",
    "IndicatorStatistics",
    "IndicatorTypeCount",
    # relationship / graph
    "RelationshipOut",
    "RelationshipPage",
    "GraphNode",
    "GraphEdge",
    "GraphResponse",
    "GraphQuery",
    # finding
    "FindingCreate",
    "FindingUpdate",
    "FindingOut",
    "FindingPage",
    # analysis
    "AnalysisRequest",
    "AnalysisJobOut",
    "AnalysisJobDetail",
    "AnalysisJobPage",
    "AnalysisRunResponse",
    "AnalysisSkip",
    "ToolInfo",
    # integration
    "IntegrationStatusOut",
    "IntegrationCheckResult",
    # timeline
    "TimelineEntry",
    "TimelineGap",
    "TimelineResponse",
    "TimelineBucket",
    "TimelineHistogram",
    # memory
    "MemorySearchRequest",
    "MemoryMatch",
    "MemoryCaseSummary",
    "MemorySearchResponse",
    "MemoryOverview",
    # search
    "SearchRequest",
    "SearchHit",
    "SearchResponse",
    "SearchTypeCount",
    # report
    "ReportRequest",
    "ReportOut",
    "ReportFileInfo",
    # ai
    "ExplainRequest",
    "ExplainResponse",
    "AI_DISCLAIMER",
    # activity / dashboard
    "ActivityOut",
    "ActivityPage",
    "DashboardSummary",
    "DashboardTotals",
    "SeverityCount",
]