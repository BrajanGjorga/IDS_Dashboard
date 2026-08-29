from __future__ import annotations

import re
from copy import deepcopy

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models import Alert, Server, User


PASSWORD = "correct-horse-battery-staple"
VALID_ALERT = {
    "event_id": "evt-2026-0001",
    "server_name": "untrusted-payload-name",
    "timestamp": "2026-08-16T12:30:00Z",
    "prediction": "MALICIOUS",
    "predicted_label": "MALICIOUS",
    "confidence": 0.99,
    "source_csv": "capture.pcap_Flow.csv",
    "model_version": None,
    "flow": {
        "Flow ID": "10.0.2.15-172.236.195.26-46889-123-17",
        "Src IP": "10.0.2.15",
        "Src Port": 46889,
        "Dst IP": "172.236.195.26",
        "Dst Port": 123,
        "Protocol": 17,
        "Flow Duration": 41555,
    },
}


def register_user(
    client: TestClient,
    email: str = "owner@example.com",
    username: str | None = None,
):
    resolved_username = username or email.partition("@")[0]
    return client.post(
        "/register",
        data={
            "username": resolved_username,
            "email": email,
            "password": PASSWORD,
            "password_confirm": PASSWORD,
        },
        follow_redirects=False,
    )


def login_user(client: TestClient, email: str = "owner@example.com"):
    return client.post(
        "/login",
        data={"email": email, "password": PASSWORD, "next": "/"},
        follow_redirects=False,
    )


def logout_user(client: TestClient):
    return client.post("/logout", follow_redirects=False)


def register_server(client: TestClient, name: str = "monitored-server-1") -> tuple[int, str]:
    response = client.post("/servers/register", data={"server_name": name})
    assert response.status_code == 200
    match = re.search(r"PREDICTION_AGENT_API_TOKEN=([A-Za-z0-9_-]+)", response.text)
    assert match is not None
    token = match.group(1)
    assert response.text.count(token) == 1
    assert response.headers["cache-control"] == "no-store"
    with client.app.state.session_factory() as session:
        server = session.scalar(select(Server).where(Server.server_name == name))
        assert server is not None
        return server.id, token


def post_alert(client: TestClient, token: str | None = None, **changes):
    payload = deepcopy(VALID_ALERT)
    payload.update(changes)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post("/api/alerts", json=payload, headers=headers)


def test_user_registration_hashes_password_and_starts_session(client: TestClient):
    response = register_user(client, "Owner@Example.com", "Security_Owner")

    assert response.status_code == 303
    assert response.headers["location"] == "/servers/register"
    assert client.get("/").status_code == 200
    with client.app.state.session_factory() as session:
        user = session.scalar(select(User))
        assert user is not None
        assert user.username == "security_owner"
        assert user.email == "owner@example.com"
        assert user.password_hash != PASSWORD
        assert user.password_hash.startswith("scrypt$")

    dashboard = client.get("/")
    assert "security_owner" in dashboard.text
    assert "owner@example.com" not in dashboard.text


def test_registration_rejects_duplicate_and_invalid_usernames(client: TestClient):
    register_user(client, "first@example.com", "analyst-one")
    logout_user(client)

    duplicate = register_user(client, "second@example.com", "Analyst-One")
    invalid = register_user(client, "third@example.com", "no spaces allowed")

    assert duplicate.status_code == 400
    assert "username is already taken" in duplicate.text
    assert invalid.status_code == 400
    assert "Username must be 3–30 characters" in invalid.text


def test_user_login(client: TestClient):
    register_user(client)
    logout_user(client)

    invalid = client.post(
        "/login",
        data={"email": "owner@example.com", "password": "wrong-password", "next": "/"},
    )
    valid = login_user(client)

    assert invalid.status_code == 401
    assert "Invalid email or password" in invalid.text
    assert valid.status_code == 303
    assert valid.headers["location"] == "/"


def test_user_can_register_server_and_plaintext_token_is_not_stored(client: TestClient):
    register_user(client)
    server_id, token = register_server(client)

    assert len(token) >= 40
    with client.app.state.session_factory() as session:
        server = session.get(Server, server_id)
        assert server is not None
        assert server.api_token_hash != token
        assert token not in server.api_token_hash
        assert len(server.api_token_hash) == 64
        assert server.active is True


def test_alert_ingestion_requires_valid_token(client: TestClient):
    missing = post_alert(client)
    invalid = post_alert(client, "not-a-valid-token")

    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert invalid.status_code == 401


def test_valid_token_links_alert_to_authenticated_server(client: TestClient):
    register_user(client)
    server_id, token = register_server(client, "authenticated-server")

    response = post_alert(client, token)

    assert response.status_code == 201
    alert = response.json()["alert"]
    assert alert["server_id"] == server_id
    assert alert["server_name"] == "authenticated-server"
    assert alert["source_ip"] == "10.0.2.15"
    assert alert["source_port"] == 46889
    assert alert["destination_ip"] == "172.236.195.26"
    assert alert["destination_port"] == 123
    assert alert["protocol"] == "17"
    assert alert["flow_duration"] == 41555.0
    assert alert["flow"] == VALID_ALERT["flow"]
    with client.app.state.session_factory() as session:
        server = session.get(Server, server_id)
        stored_alert = session.scalar(select(Alert))
        assert server is not None and server.last_seen_at is not None
        assert stored_alert is not None and stored_alert.server_id == server_id


def test_top_level_network_fields_remain_compatible(client: TestClient):
    register_user(client)
    _, token = register_server(client)

    response = post_alert(
        client,
        token,
        event_id="top-level-network-fields",
        source_ip="192.0.2.10",
        source_port=51000,
        destination_ip="198.51.100.20",
        destination_port=443,
        protocol=6,
        flow_duration=100.5,
    )

    assert response.status_code == 201
    alert = response.json()["alert"]
    assert alert["source_ip"] == "192.0.2.10"
    assert alert["source_port"] == 51000
    assert alert["destination_ip"] == "198.51.100.20"
    assert alert["destination_port"] == 443
    assert alert["protocol"] == "6"


def test_disabled_server_token_returns_403(client: TestClient):
    register_user(client)
    server_id, token = register_server(client)
    disabled = client.post(f"/servers/{server_id}/disable", follow_redirects=False)

    response = post_alert(client, token)

    assert disabled.status_code == 303
    assert response.status_code == 403
    assert response.json()["detail"] == "Server is disabled"


def test_duplicate_event_id_protection_remains_idempotent(client: TestClient):
    register_user(client)
    _, token = register_server(client)

    first = post_alert(client, token)
    duplicate = post_alert(client, token, confidence=0.25)
    listing = client.get("/api/alerts")

    assert first.status_code == 201
    assert duplicate.status_code == 200
    assert duplicate.json()["created"] is False
    assert duplicate.json()["alert"]["confidence"] == 0.99
    assert listing.json()["total"] == 1


def test_same_event_id_from_another_server_returns_conflict(client: TestClient):
    register_user(client)
    _, first_token = register_server(client, "server-one")
    _, second_token = register_server(client, "server-two")
    assert post_alert(client, first_token).status_code == 201

    response = post_alert(client, second_token)

    assert response.status_code == 409


def test_user_cannot_see_another_users_servers_or_alerts(client: TestClient):
    register_user(client, "alice@example.com")
    alice_server_id, alice_token = register_server(client, "alice-private-server")
    alice_alert_id = post_alert(client, alice_token).json()["alert"]["id"]
    logout_user(client)

    register_user(client, "bob@example.com")
    bob_server_id, bob_token = register_server(client, "bob-server")
    bob_alert_id = post_alert(client, bob_token, event_id="bob-event").json()["alert"]["id"]

    servers_page = client.get("/servers")
    api_alerts = client.get("/api/alerts")
    dashboard = client.get("/")

    assert "bob-server" in servers_page.text
    assert "alice-private-server" not in servers_page.text
    assert api_alerts.json()["total"] == 1
    assert api_alerts.json()["items"][0]["id"] == bob_alert_id
    assert "10.0.2.15" in dashboard.text
    assert client.get(f"/servers/{alice_server_id}/alerts").status_code == 404
    assert client.post(f"/servers/{alice_server_id}/disable").status_code == 404
    assert client.get(f"/alerts/{alice_alert_id}").status_code == 404
    assert client.get(f"/api/alerts/{alice_alert_id}").status_code == 404
    assert bob_server_id != alice_server_id
    with client.app.state.session_factory() as session:
        alice_server = session.get(Server, alice_server_id)
        assert alice_server is not None and alice_server.active is True


def test_user_cannot_acknowledge_another_users_alert(client: TestClient):
    register_user(client, "alice@example.com")
    _, alice_token = register_server(client, "alice-server")
    alice_alert_id = post_alert(client, alice_token).json()["alert"]["id"]
    logout_user(client)
    register_user(client, "bob@example.com")

    page_response = client.post(f"/alerts/{alice_alert_id}/acknowledge")
    api_response = client.post(f"/api/alerts/{alice_alert_id}/acknowledge")

    assert page_response.status_code == 404
    assert api_response.status_code == 404
    with client.app.state.session_factory() as session:
        alert = session.get(Alert, alice_alert_id)
        assert alert is not None and alert.acknowledged is False


def test_retrieve_and_acknowledge_own_alert(client: TestClient):
    register_user(client)
    server_id, token = register_server(client)
    alert_id = post_alert(client, token).json()["alert"]["id"]

    filtered = client.get(
        "/api/alerts",
        params={"server_id": server_id, "prediction": "malicious", "limit": 1},
    )
    acknowledged = client.post(f"/api/alerts/{alert_id}/acknowledge")

    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1
    assert acknowledged.status_code == 200
    assert acknowledged.json()["acknowledged"] is True
    assert acknowledged.json()["acknowledged_at"] is not None


def test_validation_errors_are_clear_after_authentication(client: TestClient):
    register_user(client)
    _, token = register_server(client)
    missing_event_id = deepcopy(VALID_ALERT)
    missing_event_id.pop("event_id")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post("/api/alerts", json=missing_event_id, headers=headers)
    invalid_confidence = post_alert(
        client, token, event_id="invalid-confidence", confidence=1.5
    )

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"][-1] == "event_id"
    assert invalid_confidence.status_code == 422


def test_dashboard_filters_accept_empty_date_fields(client: TestClient):
    register_user(client)
    server_id, token = register_server(client)
    post_alert(client, token)

    response = client.get(
        "/",
        params={
            "server_id": server_id,
            "prediction": "MALICIOUS",
            "acknowledged": "false",
            "start": "",
            "end": "",
        },
    )

    assert response.status_code == 200
    assert "1 matching" in response.text
    assert "10.0.2.15" in response.text


def test_dashboard_filters_accept_all_servers_option(client: TestClient):
    register_user(client)
    _, token = register_server(client)
    post_alert(client, token)

    response = client.get(
        "/",
        params={
            "server_id": "",
            "prediction": "",
            "acknowledged": "",
            "start": "",
            "end": "",
        },
    )

    assert response.status_code == 200
    assert "1 matching" in response.text
    assert "10.0.2.15" in response.text


def test_view_server_alerts_only_shows_that_servers_alerts(client: TestClient):
    register_user(client)
    first_server_id, first_token = register_server(client, "web-server")
    _, second_token = register_server(client, "database-server")
    post_alert(client, first_token, event_id="web-alert", source_ip="192.0.2.10")
    post_alert(
        client,
        second_token,
        event_id="database-alert",
        source_ip="198.51.100.20",
        prediction="BENIGN",
        predicted_label="BENIGN",
    )

    response = client.get(f"/servers/{first_server_id}/alerts")

    assert response.status_code == 200
    assert response.history[0].headers["location"] == f"/?server_id={first_server_id}"
    assert "<h1>web-server</h1>" in response.text
    assert "192.0.2.10" in response.text
    assert "198.51.100.20" not in response.text
    assert "<strong>1</strong>" in response.text


def test_logged_out_user_is_redirected_and_api_is_unauthorized(client: TestClient):
    dashboard = client.get("/", follow_redirects=False)
    api = client.get("/api/alerts")

    assert dashboard.status_code == 303
    assert dashboard.headers["location"] == "/login"
    assert api.status_code == 401


def test_health_endpoint_reports_database_without_login(client: TestClient):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "application": "running",
        "database": "available",
    }
