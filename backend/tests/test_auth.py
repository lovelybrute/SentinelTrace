import json

import auth
from config import settings


def test_password_hash_round_trip():
    encoded = auth.hash_password("correct horse battery staple", iterations=1_000)
    assert auth.verify_password("correct horse battery staple", encoded)
    assert not auth.verify_password("wrong", encoded)


def test_login_disabled_without_users(client, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_USERS_JSON", "")
    response = client.post("/auth/login", json={"email": "analyst@example.com", "password": "secret"})
    assert response.status_code == 503


def test_login_and_me(client, monkeypatch):
    password_hash = auth.hash_password("A-strong-test-password", iterations=1_000)
    users = {"analyst@example.com": {"password_hash": password_hash, "display_name": "Test Analyst", "role": "SOC_ANALYST", "unit": "Test SOC", "analyst_id": "T-01"}}
    monkeypatch.setattr(settings, "AUTH_USERS_JSON", json.dumps(users))
    response = client.post("/auth/login", json={"email": "analyst@example.com", "password": "A-strong-test-password"})
    assert response.status_code == 200
    token = response.json()["access_token"]
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["analystId"] == "T-01"


def test_login_rejects_wrong_password(client, monkeypatch):
    users = {"analyst@example.com": {"password_hash": auth.hash_password("right", iterations=1_000)}}
    monkeypatch.setattr(settings, "AUTH_USERS_JSON", json.dumps(users))
    response = client.post("/auth/login", json={"email": "analyst@example.com", "password": "wrong"})
    assert response.status_code == 401
