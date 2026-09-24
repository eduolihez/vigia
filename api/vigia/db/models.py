"""SQLModel schema for Vigía: Scan, Asset, Finding, Evidence, ToolCall, Setting, ApiKey.

See docs/architecture.md and section 8 of the project brief for the data model rationale.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


def _now() -> datetime:
    return datetime.now(UTC)


def _uuid() -> str:
    return str(uuid4())


class ScanMode(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class AssetType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    SERVICE = "service"
    URL = "url"
    EMAIL_CONFIG = "email_config"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ToolCallStatus(StrEnum):
    PENDING = "pending"
    SUCCESS = "success"
    ERROR = "error"
    REJECTED = "rejected"


class Scan(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    domain: str = Field(index=True)
    mode: ScanMode = Field(default=ScanMode.PASSIVE)
    planner_model: str
    extractor_model: str
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    budget_max_steps: int = Field(default=60)
    budget_max_minutes: int = Field(default=20)
    verified: bool = Field(default=False)
    verification_token: str | None = Field(default=None)
    started_at: datetime | None = Field(default=None)
    finished_at: datetime | None = Field(default=None)
    created_at: datetime = Field(default_factory=_now)


class Asset(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    type: AssetType
    value: str = Field(index=True)
    parent_id: str | None = Field(default=None, foreign_key="asset.id")
    asset_metadata: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    first_seen: datetime = Field(default_factory=_now)
    last_seen: datetime = Field(default_factory=_now)


class Finding(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    asset_id: str | None = Field(default=None, foreign_key="asset.id")
    type: str
    severity: FindingSeverity
    score: float
    title: str
    explanation: str
    remediation: str
    kev: bool = Field(default=False)
    epss: float | None = Field(default=None)
    cve: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=_now)


class Evidence(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    finding_id: str | None = Field(default=None, foreign_key="finding.id", index=True)
    asset_id: str | None = Field(default=None, foreign_key="asset.id", index=True)
    tool: str
    raw_output: bytes
    sha256: str
    created_at: datetime = Field(default_factory=_now)


class ToolCall(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    phase: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    reason: str
    status: ToolCallStatus = Field(default=ToolCallStatus.PENDING)
    duration_ms: int | None = Field(default=None)
    result_sha256: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=_now)


class Setting(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: str
    updated_at: datetime = Field(default_factory=_now)


class ApiKey(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    source: str = Field(index=True, unique=True)
    encrypted_value: bytes
    created_at: datetime = Field(default_factory=_now)
