"""Structured report shape (brief section 7.1): what the Report Writer produces."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TopRisk(BaseModel):
    title: str
    reason: str


class ReportFinding(BaseModel):
    title: str
    explanation: str
    impact: str
    remediation: str


class ReportDraft(BaseModel):
    executive_summary: str
    top_risks: list[TopRisk] = Field(default_factory=list)
    findings: list[ReportFinding] = Field(default_factory=list)
    positive_observations: list[str] = Field(default_factory=list)
