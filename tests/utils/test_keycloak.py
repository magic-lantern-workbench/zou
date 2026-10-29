import base64
import json
from unittest import mock

import pytest
import requests

from zou.app import app, config
from zou.app.exceptions import WrongPasswordException
from zou.app.utils import keycloak


def make_token(claims):
    def encode(data):
        raw = json.dumps(data).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{encode({'alg': 'RS256'})}.{encode(claims)}.signature"


def token_response(claims, status_code=200, error=None):
    response = mock.Mock()
    response.status_code = status_code
    response.json.return_value = (
        {"error": error} if error else {"access_token": make_token(claims)}
    )
    return response


@pytest.fixture(autouse=True)
def keycloak_config(monkeypatch):
    monkeypatch.setattr(config, "KEYCLOAK_SERVER_URL", "http://kc:8080/")
    monkeypatch.setattr(config, "KEYCLOAK_REALM", "mlw")
    monkeypatch.setattr(config, "KEYCLOAK_CLIENT_ID", "kitsu")
    monkeypatch.setattr(config, "KEYCLOAK_CLIENT_SECRET", "s3cret")
    monkeypatch.setattr(config, "KEYCLOAK_DEFAULT_ROLE", "user")
    monkeypatch.setattr(
        config,
        "KEYCLOAK_ROLE_MAP",
        ["mlw-admin:admin", "mlw-manager:manager", "mlw-artist:user"],
    )


def test_token_url_is_built_from_server_and_realm():
    assert keycloak.get_token_url() == (
        "http://kc:8080/realms/mlw/protocol/openid-connect/token"
    )


def test_realm_and_client_roles_are_collected():
    claims = {
        "realm_access": {"roles": ["mlw-artist"]},
        "resource_access": {"kitsu": {"roles": ["mlw-manager"]}},
    }
    assert keycloak.get_roles(claims) == {"mlw-artist", "mlw-manager"}


def test_roles_of_another_client_are_ignored():
    claims = {"resource_access": {"other": {"roles": ["mlw-admin"]}}}
    assert keycloak.get_roles(claims) == set()


def test_the_most_privileged_mapped_role_wins():
    claims = {"realm_access": {"roles": ["mlw-artist", "mlw-admin"]}}
    assert keycloak.get_role(claims) == "admin"


def test_unmapped_roles_fall_back_to_the_default_role():
    claims = {"realm_access": {"roles": ["offline_access"]}}
    assert keycloak.get_role(claims) == "user"


def test_authenticate_returns_the_access_token_claims():
    claims = {"email": "a@b.test", "given_name": "Ada"}
    with mock.patch(
        "zou.app.utils.keycloak.requests.post",
        return_value=token_response(claims),
    ) as post:
        assert keycloak.authenticate("a@b.test", "pw") == claims
    sent = post.call_args.kwargs["data"]
    assert sent["grant_type"] == "password"
    assert sent["client_id"] == "kitsu"
    assert sent["username"] == "a@b.test"


def test_authenticate_refuses_wrong_credentials():
    with mock.patch(
        "zou.app.utils.keycloak.requests.post",
        return_value=token_response(
            {}, status_code=401, error="invalid_grant"
        ),
    ):
        with pytest.raises(WrongPasswordException):
            keycloak.authenticate("a@b.test", "wrong")


def test_a_misconfigured_client_is_not_a_wrong_password():
    with mock.patch(
        "zou.app.utils.keycloak.requests.post",
        return_value=token_response(
            {}, status_code=400, error="unauthorized_client"
        ),
    ):
        with app.app_context(), pytest.raises(TimeoutError):
            keycloak.authenticate("a@b.test", "pw")


def test_a_public_client_sends_no_secret(monkeypatch):
    monkeypatch.setattr(config, "KEYCLOAK_CLIENT_SECRET", "")
    with mock.patch(
        "zou.app.utils.keycloak.requests.post",
        return_value=token_response({"email": "a@b.test"}),
    ) as post:
        keycloak.authenticate("a@b.test", "pw")
    assert "client_secret" not in post.call_args.kwargs["data"]


def test_authenticate_reports_an_unreachable_server_as_a_timeout():
    with mock.patch(
        "zou.app.utils.keycloak.requests.post",
        side_effect=requests.ConnectionError(),
    ):
        with app.app_context(), pytest.raises(TimeoutError):
            keycloak.authenticate("a@b.test", "pw")


def test_map_claims_keeps_only_populated_names():
    claims = {"given_name": "Ada", "family_name": ""}
    assert keycloak.map_claims(claims) == {"first_name": "Ada"}
