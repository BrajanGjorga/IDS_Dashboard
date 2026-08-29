from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, TypeVar

from sqlalchemy import Select, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Alert, Server, User
from app.schemas import AlertCreate, as_utc
from app.security import generate_api_token, hash_api_token, hash_password, verify_password


T = TypeVar("T")
MALICIOUS_LABELS = ("MALICIOUS", "ATTACK")


class DuplicateEventOwnershipError(Exception):
    pass


def normalize_email(email: str) -> str:
    return email.strip().casefold()


def normalize_username(username: str) -> str:
    return username.strip().casefold()


def create_user(session: Session, username: str, email: str, password: str) -> User:
    user = User(
        username=normalize_username(username),
        email=normalize_email(email),
        password_hash=hash_password(password),
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def authenticate_user(session: Session, email: str, password: str) -> User | None:
    user = session.scalar(select(User).where(User.email == normalize_email(email)))
    if user is None or not verify_password(password, user.password_hash):
        return None
    return user


def register_server(session: Session, user: User, server_name: str) -> tuple[Server, str]:
    plaintext_token = generate_api_token()
    server = Server(
        user_id=user.id,
        server_name=server_name.strip(),
        api_token_hash=hash_api_token(plaintext_token),
    )
    session.add(server)
    session.commit()
    session.refresh(server)
    return server, plaintext_token


def server_from_api_token(session: Session, token: str) -> Server | None:
    return session.scalar(
        select(Server).where(Server.api_token_hash == hash_api_token(token))
    )


def get_owned_server(session: Session, user_id: int, server_id: int) -> Server | None:
    return session.scalar(
        select(Server).where(Server.id == server_id, Server.user_id == user_id)
    )


def get_owned_alert(session: Session, user_id: int, alert_id: int) -> Alert | None:
    return session.scalar(
        select(Alert)
        .join(Server, Alert.server_id == Server.id)
        .where(Alert.id == alert_id, Server.user_id == user_id)
    )


def _flow_value(
    explicit: T | None,
    flow: dict[str, Any],
    keys: tuple[str, ...],
    converter: Callable[[Any], T],
) -> T | None:
    if explicit is not None:
        try:
            return converter(explicit)
        except (TypeError, ValueError, OverflowError):
            return None
    normalized = {str(key).strip().casefold(): value for key, value in flow.items()}
    for key in keys:
        value = normalized.get(key.casefold())
        if value is None or value == "":
            continue
        try:
            return converter(value)
        except (TypeError, ValueError, OverflowError):
            return None
    return None


def _to_int(value: Any) -> int:
    converted = float(value)
    if not converted.is_integer():
        raise ValueError("port is not an integer")
    result = int(converted)
    if not 0 <= result <= 65535:
        raise ValueError("port is outside the valid range")
    return result


def alert_from_payload(payload: AlertCreate, server: Server) -> Alert:
    flow = payload.flow
    prediction = payload.prediction or payload.predicted_label
    predicted_label = payload.predicted_label or payload.prediction
    return Alert(
        server_id=server.id,
        event_id=payload.event_id,
        server_name=server.server_name,
        timestamp=payload.timestamp or datetime.now(timezone.utc),
        prediction=prediction,
        predicted_label=predicted_label,
        confidence=payload.confidence,
        source_csv=payload.source_csv,
        model_version=payload.model_version,
        source_ip=_flow_value(payload.source_ip, flow, ("Src IP", "source_ip", "src_ip"), str),
        destination_ip=_flow_value(
            payload.destination_ip,
            flow,
            ("Dst IP", "destination_ip", "dest_ip", "dst_ip"),
            str,
        ),
        source_port=_flow_value(
            payload.source_port, flow, ("Src Port", "source_port", "src_port"), _to_int
        ),
        destination_port=_flow_value(
            payload.destination_port,
            flow,
            ("Dst Port", "destination_port", "dest_port", "dst_port"),
            _to_int,
        ),
        protocol=_flow_value(payload.protocol, flow, ("Protocol", "protocol"), str),
        flow_duration=_flow_value(
            payload.flow_duration, flow, ("Flow Duration", "flow_duration"), float
        ),
        flow=flow,
    )


def create_or_get_alert(
    session: Session, payload: AlertCreate, server: Server
) -> tuple[Alert, bool]:
    existing = session.scalar(select(Alert).where(Alert.event_id == payload.event_id))
    if existing is not None:
        if existing.server_id != server.id:
            raise DuplicateEventOwnershipError
        server.last_seen_at = datetime.now(timezone.utc)
        session.commit()
        return existing, False

    alert = alert_from_payload(payload, server)
    server.last_seen_at = datetime.now(timezone.utc)
    session.add(alert)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        existing = session.scalar(select(Alert).where(Alert.event_id == payload.event_id))
        if existing is None:
            raise
        if existing.server_id != server.id:
            raise DuplicateEventOwnershipError
        server.last_seen_at = datetime.now(timezone.utc)
        session.commit()
        return existing, False
    session.refresh(alert)
    return alert, True


def apply_alert_filters(
    statement: Select[tuple[Alert]],
    *,
    user_id: int,
    server_id: int | None = None,
    server_name: str | None = None,
    prediction: str | None = None,
    acknowledged: bool | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> Select[tuple[Alert]]:
    statement = statement.where(
        Alert.server_id.in_(select(Server.id).where(Server.user_id == user_id))
    )
    if server_id is not None:
        statement = statement.where(Alert.server_id == server_id)
    if server_name:
        statement = statement.where(
            Alert.server_id.in_(
                select(Server.id).where(
                    Server.user_id == user_id,
                    Server.server_name == server_name,
                )
            )
        )
    if prediction:
        statement = statement.where(func.upper(Alert.prediction) == prediction.upper())
    if acknowledged is not None:
        statement = statement.where(Alert.acknowledged.is_(acknowledged))
    if start:
        statement = statement.where(Alert.timestamp >= as_utc(start))
    if end:
        statement = statement.where(Alert.timestamp <= as_utc(end))
    return statement


def list_alerts(
    session: Session,
    *,
    user_id: int,
    server_id: int | None = None,
    server_name: str | None = None,
    prediction: str | None = None,
    acknowledged: bool | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Alert], int]:
    filtered = apply_alert_filters(
        select(Alert),
        user_id=user_id,
        server_id=server_id,
        server_name=server_name,
        prediction=prediction,
        acknowledged=acknowledged,
        start=start,
        end=end,
    )
    total = session.scalar(select(func.count()).select_from(filtered.subquery())) or 0
    items = list(
        session.scalars(
            filtered.order_by(Alert.timestamp.desc(), Alert.id.desc()).limit(limit).offset(offset)
        )
    )
    return items, total


def acknowledge_alert(session: Session, alert: Alert) -> Alert:
    if not alert.acknowledged:
        alert.acknowledged = True
        alert.acknowledged_at = datetime.now(timezone.utc)
        session.commit()
        session.refresh(alert)
    return alert


def is_malicious(alert: Alert) -> bool:
    label = (alert.prediction or alert.predicted_label or "").upper()
    return label in MALICIOUS_LABELS
