"""Unified IntelItem schema shared with module A."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class CVSS(BaseModel):
    score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    vector: Optional[str] = None
    severity: Optional[str] = None
    source: Optional[str] = None
    confidence: str = Field(default="high", description="high / medium / low")


class POC(BaseModel):
    repo_url: Optional[str] = None
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None
    status: str = Field(default="unverified", description="unverified / success / failed")


class AffectedAssets(BaseModel):
    exposed_count: int = 0
    top_countries: List[str] = Field(default_factory=list)
    sample_ips: List[str] = Field(default_factory=list)
    query_time: Optional[datetime] = None


class RelatedPaper(BaseModel):
    title: Optional[str] = None
    arxiv_id: Optional[str] = None
    authors: List[str] = Field(default_factory=list)
    abstract: Optional[str] = None
    similarity_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class AttackStep(BaseModel):
    tactic: Optional[str] = None
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    description: Optional[str] = None


class Remediation(BaseModel):
    cve_id: Optional[str] = None
    vendor: Optional[str] = None
    affected_versions: List[str] = Field(default_factory=list)
    patch_url: Optional[str] = None
    mitigation_steps: List[str] = Field(default_factory=list)
    workaround: Optional[str] = None
    verified: bool = False
    status: str = Field(default="official_patch", description="official_patch / temporary_mitigation")


class Enrichment(BaseModel):
    cvss: Optional[CVSS] = None
    poc: Optional[POC] = None
    affected_assets: Optional[AffectedAssets] = None
    related_papers: List[RelatedPaper] = Field(default_factory=list)
    attack_chain: List[AttackStep] = Field(default_factory=list)
    remediation: Optional[Remediation] = None


class IntelItem(BaseModel):
    intel_id: str = Field(..., description="Unique ID such as CVE-2024-XXXX")
    source: str = Field(..., description="Source identifier such as nvd / ghsa / arxiv")
    title: str
    description: str
    publish_time: datetime = Field(..., description="UTC time in ISO 8601")
    raw_url: Optional[str] = None
    ai_relevant: bool = True
    tags: List[str] = Field(default_factory=list)
    fingerprint: Optional[str] = None
    last_check_time: Optional[datetime] = None
    enrichment: Enrichment = Field(default_factory=Enrichment)
