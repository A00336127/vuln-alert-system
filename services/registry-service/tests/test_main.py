"""
Unit tests for the registry service.
"""
import os
from unittest.mock import patch

os.environ["AWS_REGION"]   = "eu-west-1"
os.environ["STACKS_TABLE"] = "test-stacks"
os.environ["USERS_TABLE"]  = "test-users"
os.environ["JWT_SECRET"]   = "test-secret"

with patch("boto3.resource"):
    from main import app

from fastapi.testclient import TestClient
client = TestClient(app)


def test_health_returns_200():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["service"] == "registry"


def test_login_fails_with_wrong_credentials():
    with patch("main.users_table") as mock_table:
        mock_table.get_item.return_value = {}
        response = client.post(
            "/auth/login",
            json={"username": "nobody", "password": "wrong"}
        )
    assert response.status_code == 401


def test_create_stack_requires_authentication():
    response = client.post(
        "/stacks",
        json={
            "package":   "django",
            "version":   "4.2.0",
            "ecosystem": "PyPI"
        }
    )
    assert response.status_code == 403
