from __future__ import annotations

import json
import re
import secrets
from collections.abc import Generator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Query, Request, Response, status
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BeforeValidator
from sqlalchemy import Engine, func, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.config import PROJECT_ROOT, Settings
from app.database import create_db_engine, create_session_factory
from app.logging_config import configure_logging
from app.models import Alert, Server, User
from app.schemas import AlertCreate, AlertCreated, AlertList, AlertRead
from app.services import (
    MALICIOUS_LABELS,
    DuplicateEventOwnershipError,
    acknowledge_alert,
    authenticate_user,
    create_or_get_alert,
    create_user,
    get_owned_alert,
    get_owned_server,
    is_malicious,
    list_alerts,
    normalize_email,
    normalize_username,
    register_server,
    server_from_api_token,
)


TEMPLATES_DIR = PROJECT_ROOT / "app" / "templates"
STATIC_DIR = PROJECT_ROOT / "app" / "static"


def empty_string_as_none(value: object) -> object:
    return None if value == "" else value


OptionalDashboardDatetime = Annotated[
    datetime | None, BeforeValidator(empty_string_as_none)
]
OptionalDashboardServerId = Annotated[int | None, BeforeValidator(empty_string_as_none)]


def get_session(request: Request) -> Generator[Session, None, None]:
    session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


SessionDependency = Annotated[Session, Depends(get_session)]


def session_user(request: Request, session: Session) -> User | None:
    user_id = request.session.get("user_id")
    if not isinstance(user_id, int):
        return None
    user = session.get(User, user_id)
    if user is None:
        request.session.clear()
    return user


def require_api_user(request: Request, session: Session) -> User:
    user = session_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="Login required")
    return user


def safe_redirect_target(value: str | None) -> str:
    if value and value.startswith("/") and not value.startswith("//"):
        return value
    return "/"


def bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.casefold() != "bearer" or not token.strip():
        return None
    return token.strip()


def create_app(settings: Settings | None = None, engine: Engine | None = None) -> FastAPI:
    app_settings = settings or Settings.from_env()
    db_engine = engine or create_db_engine(app_settings.database_url)
    session_factory = create_session_factory(db_engine)
    logger = configure_logging(app_settings.log_file, app_settings.log_level)
    session_secret = app_settings.session_secret or secrets.token_urlsafe(48)
    if not app_settings.session_secret:
        logger.warning(
            "SESSION_SECRET is not configured; browser sessions will reset when the app restarts"
        )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        logger.info("Alert dashboard starting")
        yield
        db_engine.dispose()
        logger.info("Alert dashboard stopped")

    application = FastAPI(
        title="Intrusion Alert Dashboard",
        version="1.1.0",
        lifespan=lifespan,
    )
    application.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        session_cookie="alert_dashboard_session",
        max_age=8 * 60 * 60,
        same_site="lax",
        https_only=app_settings.session_https_only,
    )
    application.state.engine = db_engine
    application.state.session_factory = session_factory
    application.state.settings = app_settings
    application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    templates = Jinja2Templates(directory=TEMPLATES_DIR)
    templates.env.filters["pretty_json"] = lambda value: json.dumps(
        value, indent=2, sort_keys=True, default=str
    )
    templates.env.globals["is_malicious"] = is_malicious

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        logger.warning("Invalid request for %s: %s", request.url.path, exc.errors())
        return await request_validation_exception_handler(request, exc)

    @application.exception_handler(SQLAlchemyError)
    async def database_error_handler(request: Request, exc: SQLAlchemyError):
        logger.exception("Database failure while handling %s", request.url.path, exc_info=exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "Database operation failed"},
        )

    @application.get("/health")
    def health(session: SessionDependency) -> Response:
        try:
            session.execute(text("SELECT 1"))
        except SQLAlchemyError as exc:
            logger.error("Database health check failed: %s", exc)
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "unhealthy", "application": "running", "database": "unavailable"},
            )
        return JSONResponse(
            content={"status": "healthy", "application": "running", "database": "available"}
        )

    @application.get("/register", response_class=HTMLResponse)
    def register_page(request: Request, session: SessionDependency):
        if session_user(request, session) is not None:
            return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"current_user": None, "error": None, "username": "", "email": ""},
        )

    @application.post("/register", response_class=HTMLResponse)
    def register_account(
        request: Request,
        session: SessionDependency,
        username: Annotated[str, Form()],
        email: Annotated[str, Form()],
        password: Annotated[str, Form()],
        password_confirm: Annotated[str, Form()],
    ):
        normalized_username = normalize_username(username)
        normalized_email = normalize_email(email)
        error = None
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,29}", normalized_username):
            error = "Username must be 3–30 characters and use only letters, numbers, _ or -."
        elif session.scalar(
            select(User.id).where(User.username == normalized_username)
        ) is not None:
            error = "That username is already taken."
        elif len(normalized_email) > 320 or normalized_email.count("@") != 1:
            error = "Enter a valid email address."
        elif len(password) < 12:
            error = "Password must be at least 12 characters."
        elif password != password_confirm:
            error = "Passwords do not match."
        elif session.scalar(select(User.id).where(User.email == normalized_email)) is not None:
            error = "An account with that email already exists."

        if error:
            return templates.TemplateResponse(
                request=request,
                name="register.html",
                context={
                    "current_user": None,
                    "error": error,
                    "username": normalized_username,
                    "email": normalized_email,
                },
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = create_user(session, normalized_username, normalized_email, password)
        except IntegrityError:
            session.rollback()
            return templates.TemplateResponse(
                request=request,
                name="register.html",
                context={
                    "current_user": None,
                    "error": "That username or email is already registered.",
                    "username": normalized_username,
                    "email": normalized_email,
                },
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        request.session.clear()
        request.session["user_id"] = user.id
        logger.info("User registered: user_id=%s", user.id)
        return RedirectResponse("/servers/register", status_code=status.HTTP_303_SEE_OTHER)

    @application.get("/login", response_class=HTMLResponse)
    def login_page(
        request: Request,
        session: SessionDependency,
        next: str | None = None,
    ):
        if session_user(request, session) is not None:
            return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "current_user": None,
                "error": None,
                "email": "",
                "next": safe_redirect_target(next),
            },
        )

    @application.post("/login", response_class=HTMLResponse)
    def login(
        request: Request,
        session: SessionDependency,
        email: Annotated[str, Form()],
        password: Annotated[str, Form()],
        next: Annotated[str, Form()] = "/",
    ):
        user = authenticate_user(session, email, password)
        if user is None:
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={
                    "current_user": None,
                    "error": "Invalid email or password.",
                    "email": normalize_email(email),
                    "next": safe_redirect_target(next),
                },
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        request.session.clear()
        request.session["user_id"] = user.id
        logger.info("User logged in: user_id=%s", user.id)
        return RedirectResponse(safe_redirect_target(next), status_code=status.HTTP_303_SEE_OTHER)

    @application.post("/logout")
    def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)

    @application.get("/servers", response_class=HTMLResponse)
    def servers_page(request: Request, session: SessionDependency):
        user = session_user(request, session)
        if user is None:
            return RedirectResponse("/login?next=/servers", status_code=status.HTTP_303_SEE_OTHER)
        servers = list(
            session.scalars(
                select(Server).where(Server.user_id == user.id).order_by(Server.created_at.desc())
            )
        )
        return templates.TemplateResponse(
            request=request,
            name="servers.html",
            context={"current_user": user, "servers": servers},
        )

    @application.get("/servers/register", response_class=HTMLResponse)
    def register_server_page(request: Request, session: SessionDependency):
        user = session_user(request, session)
        if user is None:
            return RedirectResponse(
                "/login?next=/servers/register", status_code=status.HTTP_303_SEE_OTHER
            )
        return templates.TemplateResponse(
            request=request,
            name="register_server.html",
            context={"current_user": user, "error": None, "server_name": ""},
        )

    @application.post("/servers/register", response_class=HTMLResponse)
    def create_registered_server(
        request: Request,
        session: SessionDependency,
        server_name: Annotated[str, Form()],
    ):
        user = session_user(request, session)
        if user is None:
            return RedirectResponse(
                "/login?next=/servers/register", status_code=status.HTTP_303_SEE_OTHER
            )
        clean_name = server_name.strip()
        error = None
        if not clean_name or len(clean_name) > 255:
            error = "Server name must contain between 1 and 255 characters."
        elif session.scalar(
            select(Server.id).where(
                Server.user_id == user.id,
                Server.server_name == clean_name,
            )
        ) is not None:
            error = "You already registered a server with that name."

        if error:
            return templates.TemplateResponse(
                request=request,
                name="register_server.html",
                context={"current_user": user, "error": error, "server_name": clean_name},
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        try:
            server, plaintext_token = register_server(session, user, clean_name)
        except IntegrityError:
            session.rollback()
            return templates.TemplateResponse(
                request=request,
                name="register_server.html",
                context={
                    "current_user": user,
                    "error": "That server could not be registered. Try a different name.",
                    "server_name": clean_name,
                },
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        logger.info("Server registered: server_id=%s user_id=%s", server.id, user.id)
        return templates.TemplateResponse(
            request=request,
            name="server_created.html",
            context={
                "current_user": user,
                "server": server,
                "api_token": plaintext_token,
            },
            headers={"Cache-Control": "no-store"},
        )

    @application.post("/servers/{server_id}/disable")
    def disable_server(request: Request, server_id: int, session: SessionDependency):
        user = session_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        server = get_owned_server(session, user.id, server_id)
        if server is None:
            raise HTTPException(status_code=404, detail="Server not found")
        server.active = False
        session.commit()
        logger.info("Server disabled: server_id=%s user_id=%s", server.id, user.id)
        return RedirectResponse("/servers", status_code=status.HTTP_303_SEE_OTHER)

    @application.get("/servers/{server_id}/alerts")
    def server_alerts(request: Request, server_id: int, session: SessionDependency):
        user = session_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        if get_owned_server(session, user.id, server_id) is None:
            raise HTTPException(status_code=404, detail="Server not found")
        return RedirectResponse(f"/?server_id={server_id}", status_code=status.HTTP_303_SEE_OTHER)

    @application.post(
        "/api/alerts",
        response_model=AlertCreated,
        status_code=status.HTTP_201_CREATED,
    )
    def receive_alert(
        payload: AlertCreate,
        response: Response,
        session: SessionDependency,
        authorization: Annotated[str | None, Header()] = None,
    ):
        token = bearer_token(authorization)
        if token is None:
            raise HTTPException(
                status_code=401,
                detail="A valid Bearer server API token is required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        server = server_from_api_token(session, token)
        if server is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid server API token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not server.active:
            raise HTTPException(status_code=403, detail="Server is disabled")

        try:
            alert, created = create_or_get_alert(session, payload, server)
        except DuplicateEventOwnershipError:
            raise HTTPException(status_code=409, detail="event_id already exists") from None
        if created:
            logger.warning(
                "Alert received: event_id=%s server_id=%s prediction=%s confidence=%s",
                alert.event_id,
                server.id,
                alert.prediction,
                alert.confidence,
            )
        else:
            response.status_code = status.HTTP_200_OK
            logger.info("Duplicate alert ignored: event_id=%s server_id=%s", alert.event_id, server.id)
        return {"status": "accepted", "created": created, "alert": alert}

    @application.get("/api/alerts", response_model=AlertList)
    def get_alerts(
        request: Request,
        session: SessionDependency,
        server_id: int | None = None,
        server_name: str | None = None,
        prediction: str | None = None,
        acknowledged: bool | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        user = require_api_user(request, session)
        if server_id is not None and get_owned_server(session, user.id, server_id) is None:
            raise HTTPException(status_code=404, detail="Server not found")
        items, total = list_alerts(
            session,
            user_id=user.id,
            server_id=server_id,
            server_name=server_name,
            prediction=prediction,
            acknowledged=acknowledged,
            start=start,
            end=end,
            limit=limit,
            offset=offset,
        )
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    @application.get("/api/alerts/{alert_id}", response_model=AlertRead)
    def get_alert(request: Request, alert_id: int, session: SessionDependency):
        user = require_api_user(request, session)
        alert = get_owned_alert(session, user.id, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert

    @application.post("/api/alerts/{alert_id}/acknowledge", response_model=AlertRead)
    def acknowledge_alert_api(request: Request, alert_id: int, session: SessionDependency):
        user = require_api_user(request, session)
        alert = get_owned_alert(session, user.id, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        result = acknowledge_alert(session, alert)
        logger.info("Alert acknowledged: event_id=%s user_id=%s", result.event_id, user.id)
        return result

    @application.get("/", response_class=HTMLResponse)
    def dashboard(
        request: Request,
        session: SessionDependency,
        server_id: OptionalDashboardServerId = None,
        prediction: str | None = None,
        acknowledged: str | None = None,
        start: OptionalDashboardDatetime = None,
        end: OptionalDashboardDatetime = None,
        page: Annotated[int, Query(ge=1)] = 1,
    ):
        user = session_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        selected_server = None
        if server_id is not None:
            selected_server = get_owned_server(session, user.id, server_id)
            if selected_server is None:
                raise HTTPException(status_code=404, detail="Server not found")

        acknowledged_filter = None
        if acknowledged in {"true", "false"}:
            acknowledged_filter = acknowledged == "true"

        page_size = 25
        alerts, filtered_total = list_alerts(
            session,
            user_id=user.id,
            server_id=server_id,
            prediction=prediction,
            acknowledged=acknowledged_filter,
            start=start,
            end=end,
            limit=page_size,
            offset=(page - 1) * page_size,
        )
        owned_server_ids = select(Server.id).where(Server.user_id == user.id)
        visible_alerts = Alert.server_id.in_(owned_server_ids)
        if selected_server is not None:
            visible_alerts = visible_alerts & (Alert.server_id == selected_server.id)
        label = func.upper(func.coalesce(Alert.prediction, Alert.predicted_label, ""))
        total_alerts = session.scalar(select(func.count(Alert.id)).where(visible_alerts)) or 0
        malicious_alerts = session.scalar(
            select(func.count(Alert.id)).where(visible_alerts, label.in_(MALICIOUS_LABELS))
        ) or 0
        last_24_hours = session.scalar(
            select(func.count(Alert.id)).where(
                visible_alerts,
                Alert.received_at >= datetime.now(timezone.utc) - timedelta(hours=24),
            )
        ) or 0
        monitored_servers = (
            1
            if selected_server is not None
            else session.scalar(select(func.count(Server.id)).where(Server.user_id == user.id)) or 0
        )
        servers = list(
            session.scalars(
                select(Server).where(Server.user_id == user.id).order_by(Server.server_name)
            )
        )
        predictions = list(
            session.scalars(
                select(Alert.prediction)
                .where(visible_alerts, Alert.prediction.is_not(None))
                .distinct()
                .order_by(Alert.prediction)
            )
        )
        page_count = max(1, (filtered_total + page_size - 1) // page_size)

        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "current_user": user,
                "alerts": alerts,
                "selected_server": selected_server,
                "summary": {
                    "total": total_alerts,
                    "malicious": malicious_alerts,
                    "last_24_hours": last_24_hours,
                    "servers": monitored_servers,
                },
                "servers": servers,
                "predictions": predictions,
                "filters": {
                    "server_id": server_id,
                    "prediction": prediction or "",
                    "acknowledged": acknowledged or "",
                    "start": start.strftime("%Y-%m-%dT%H:%M") if start else "",
                    "end": end.strftime("%Y-%m-%dT%H:%M") if end else "",
                },
                "pagination": {
                    "page": page,
                    "page_count": page_count,
                    "total": filtered_total,
                },
            },
        )

    @application.get("/alerts/{alert_id}", response_class=HTMLResponse)
    def alert_detail(request: Request, alert_id: int, session: SessionDependency):
        user = session_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        alert = get_owned_alert(session, user.id, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return templates.TemplateResponse(
            request=request,
            name="alert_detail.html",
            context={"current_user": user, "alert": alert},
        )

    @application.post("/alerts/{alert_id}/acknowledge")
    def acknowledge_alert_page(
        request: Request,
        alert_id: int,
        session: SessionDependency,
        return_to: str = Query(default="detail"),
    ):
        user = session_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        alert = get_owned_alert(session, user.id, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        acknowledge_alert(session, alert)
        logger.info("Alert acknowledged from dashboard: event_id=%s user_id=%s", alert.event_id, user.id)
        destination = "/" if return_to == "dashboard" else f"/alerts/{alert.id}"
        return RedirectResponse(destination, status_code=status.HTTP_303_SEE_OTHER)

    return application


app = create_app()
