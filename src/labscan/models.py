"""Validated resource settings and portable result records."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from labscan.output.sanitize import sanitize

State = Literal["open", "closed", "filtered", "open|filtered"]


class Limits(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rate: float = Field(default=20, gt=0, le=100)
    concurrency: int = Field(default=10, ge=1, le=32)
    timeout: float = Field(default=1, ge=0.05, le=10)
    retries: int = Field(default=0, ge=0, le=2)
    max_hosts: int = Field(default=32, ge=1, le=64)
    max_ports: int = Field(default=128, ge=1, le=256)
    banner_bytes: int = Field(default=1024, ge=1, le=4096)


class PortResult(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    @field_validator("banner", "service", "product", "version", "reason")
    @classmethod
    def sanitize_text(cls, value: str | None) -> str | None:
        return sanitize(value, 4096) if value is not None else None

    host: str
    port: int
    protocol: Literal["tcp", "udp"] = "tcp"
    state: State
    reason: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str = ""


class Report(BaseModel):
    scanner_version: str
    scan_type: str
    started: str
    ended: str
    duration: float
    settings: Limits
    banners: bool = False
    discovery: str = "skip"
    results: list[PortResult]
    targets: list[str]
    ports: list[int]
