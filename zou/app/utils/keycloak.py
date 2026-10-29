import base64
import json

import requests
from flask import current_app

from zou.app import config
from zou.app.exceptions import WrongPasswordException

# From the least to the most privileged: when a user holds several mapped
# Keycloak roles, the last one in this list is the one Kitsu gets.
ROLE_PRIORITY = ["client", "vendor", "user", "supervisor", "manager", "admin"]

REQUEST_TIMEOUT = 10


def get_token_url():
    """
    Return the token endpoint of the configured Keycloak realm.
    """
    server_url = config.KEYCLOAK_SERVER_URL.rstrip("/")
    return (
        f"{server_url}/realms/{config.KEYCLOAK_REALM}"
        "/protocol/openid-connect/token"
    )


def decode_token_claims(token):
    """
    Return the claims of a JWT without checking its signature. The token is
    only ever read from the response of the token endpoint, reached over the
    configured URL, never from a client.
    """
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def authenticate(email, password):
    """
    Check the credentials against Keycloak with the password grant and return
    the claims of the access token. Raise WrongPasswordException when
    Keycloak refuses them and TimeoutError when it cannot be reached.
    """
    data = {
        "grant_type": "password",
        "client_id": config.KEYCLOAK_CLIENT_ID,
        "username": email,
        "password": password,
        "scope": "openid email profile",
    }
    # A public client has no secret.
    if config.KEYCLOAK_CLIENT_SECRET:
        data["client_secret"] = config.KEYCLOAK_CLIENT_SECRET
    try:
        response = requests.post(
            get_token_url(), data=data, timeout=REQUEST_TIMEOUT
        )
    except requests.RequestException:
        current_app.logger.exception("Keycloak cannot be reached.")
        raise TimeoutError()

    if response.status_code != 200:
        error = response.json().get("error")
        # Only invalid_grant means the credentials are wrong: the other
        # errors (unauthorized_client when direct access grants are off,
        # invalid_client...) are a setup problem, not the user's.
        if error == "invalid_grant":
            raise WrongPasswordException()
        current_app.logger.error(
            f"Keycloak answered {response.status_code} ({error}) "
            "to the login."
        )
        raise TimeoutError()

    return decode_token_claims(response.json()["access_token"])


def get_roles(claims):
    """
    Return the names of the realm roles and of the roles of our own client.
    """
    realm_roles = claims.get("realm_access", {}).get("roles", [])
    client_roles = (
        claims.get("resource_access", {})
        .get(config.KEYCLOAK_CLIENT_ID, {})
        .get("roles", [])
    )
    return set(realm_roles) | set(client_roles)


def get_role(claims):
    """
    Return the Kitsu role of a user: the most privileged one among the
    Keycloak roles mapped through KEYCLOAK_ROLE_MAP, or the default role.
    """
    role_map = dict(
        entry.split(":", 1)
        for entry in config.KEYCLOAK_ROLE_MAP
        if ":" in entry
    )
    mapped = {
        role_map[name] for name in get_roles(claims) if name in role_map
    } & set(ROLE_PRIORITY)
    return max(
        mapped, key=ROLE_PRIORITY.index, default=config.KEYCLOAK_DEFAULT_ROLE
    )


def map_claims(claims):
    """
    Map the token claims to person fields. Only populated fields are
    returned so existing values are not overwritten with empty strings.
    """
    person_info = {}
    first_name = claims.get("given_name")
    last_name = claims.get("family_name")
    if first_name:
        person_info["first_name"] = first_name
    if last_name:
        person_info["last_name"] = last_name
    return person_info
