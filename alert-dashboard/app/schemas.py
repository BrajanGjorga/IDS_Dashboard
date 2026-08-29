from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class AlertCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(min_length=1, max_length=255)
    server_name: str | None = Field(default=None, max_length=255)
    timestamp: datetime | None = None
    prediction: str | None = Field(default=None, max_length=100)
    predicted_label: str | None = Field(default=None, max_length=100)
    confidence: float | None = Field(default=None, ge=0, le=1)
    source_csv: str | None = None
    model_version: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=45)
    destination_ip: str | None = Field(default=None, max_length=45)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | int | None = None
    flow_duration: float | None = None
    flow: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime | None) -> datetime | None:
        return as_utc(value)


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    server_id: int | None
    event_id: str
    server_name: str | None
    timestamp: datetime
    prediction: str | None
    predicted_label: str | None
    confidence: float | None
    source_csv: str | None
    model_version: str | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    flow_duration: float | None
    flow: dict[str, Any]
    received_at: datetime
    acknowledged: bool
    acknowledged_at: datetime | None

    @field_validator("timestamp", "received_at", "acknowledged_at")
    @classmethod
    def normalize_datetimes(cls, value: datetime | None) -> datetime | None:
        return as_utc(value)


class AlertCreated(BaseModel):
    status: str
    created: bool
    alert: AlertRead


class AlertList(BaseModel):
    items: list[AlertRead]
    total: int
    limit: int
    offset: int
