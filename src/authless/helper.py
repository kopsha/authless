import hashlib
import webbrowser
from abc import ABC, abstractmethod
from base64 import b64encode, urlsafe_b64encode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from os import environ
from secrets import token_urlsafe
from typing import Any, Protocol
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from requests.auth import AuthBase

from .tokens import PersistentTokens


class HttpClient(Protocol):
    def post(self, url: str, *, data=None, headers=None) -> Any: ...


class AuthStrategy(ABC):
    def __init__(self, *, client_id, token_endpoint, token_store, http_client):
        self.client_id = client_id
        self.token_endpoint = token_endpoint
        self.token_store = token_store
        self.http = http_client

    @abstractmethod
    def get_header(self) -> dict:
        pass


class AuthorizationCodeStrategy(AuthStrategy):
    def __init__(
        self,
        *,
        client_id,
        token_endpoint,
        authorization_endpoint,
        redirect_uri,
        scope,
        auth_response_handler,
        token_store,
        http_client,
    ):
        super().__init__(
            client_id=client_id,
            token_endpoint=token_endpoint,
            token_store=token_store,
            http_client=http_client,
        )
        self.authorization_endpoint = authorization_endpoint
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.auth_response_handler = auth_response_handler

    def get_header(self):
        if self.token_store.is_empty():
            self.token_store.read()

        if self.token_store.is_expired():
            if self.token_store.refresh_token:
                self._refresh()
            else:
                self._authorize()

        return self.token_store.as_header()

    def _make_pkce_params(self, code_verifier, state):
        challenge = hashlib.sha256(code_verifier.encode()).digest()
        challenge = urlsafe_b64encode(challenge).rstrip(b"=").decode()

        return dict(
            response_type="code",
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            scope=" ".join(self.scope),
            code_challenge_method="S256",
            code_challenge=challenge,
            state=state,
        )

    def _authorize(self):
        code_verifier = token_urlsafe(48)
        state = token_urlsafe(16)

        params = self._make_pkce_params(code_verifier, state)
        login_url = f"{self.authorization_endpoint}?{urlencode(params)}"

        response_path = self.auth_response_handler(login_url)
        parsed = urlparse(response_path)
        q = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if q.get("state") != state:
            raise ValueError("State mismatch")

        if "error" in q:
            raise ValueError(q.get("error_description"))

        data = dict(
            grant_type="authorization_code",
            code=q["code"],
            redirect_uri=self.redirect_uri,
            client_id=self.client_id,
            code_verifier=code_verifier,
        )

        r = self.http.post(self.token_endpoint, data=data)
        r.raise_for_status()
        self.token_store.write(r.json())

    def _refresh(self):
        data = dict(
            client_id=self.client_id,
            grant_type="refresh_token",
            refresh_token=self.token_store.refresh_token,
        )
        r = self.http.post(self.token_endpoint, data=data)

        r.raise_for_status()
        self.token_store.write(r.json())


class ClientCredentialsStrategy(AuthStrategy):
    def __init__(
        self, *, client_id, client_secret, token_endpoint, token_store, http_client
    ):
        super().__init__(
            client_id=client_id,
            token_endpoint=token_endpoint,
            token_store=token_store,
            http_client=http_client,
        )
        self.client_secret = client_secret

    def get_header(self):
        if self.token_store.is_empty():
            self.token_store.read()

        if self.token_store.is_expired():
            self._refresh()

        return self.token_store.as_header()

    def _refresh(self):
        creds = b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
        r = self.http.post(
            self.token_endpoint,
            headers=dict(Authorization=f"Basic {creds}"),
            data=dict(grant_type="client_credentials"),
        )

        r.raise_for_status()
        self.token_store.write(r.json())


class OAuth2Helper(AuthBase):
    def __init__(
        self,
        *,
        app: str,
        client_id: str,
        client_secret: str | None = None,
        token_endpoint: str,
        authorization_endpoint: str | None = None,
        redirect_uri: str | None = None,
        scope: tuple[str, ...] | None = None,
        auth_response_handler=None,
        http_client: HttpClient,
    ):
        self.app = app
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_endpoint = token_endpoint
        self.authorization_endpoint = authorization_endpoint
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.auth_response_handler = auth_response_handler
        self.user_token = PersistentTokens(app=app, named="user_token")
        self.app_token = PersistentTokens(app=app, named="app_token")

        self.user_strategy = AuthorizationCodeStrategy(
            client_id=client_id,
            token_endpoint=token_endpoint,
            authorization_endpoint=authorization_endpoint,
            redirect_uri=redirect_uri,
            scope=scope,
            auth_response_handler=auth_response_handler,
            token_store=self.user_token,
            http_client=http_client,
        )
        self.app_strategy = ClientCredentialsStrategy(
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint=token_endpoint,
            token_store=self.app_token,
            http_client=http_client,
        )

    def pick_strategy(self, request):
        print(request.__dict__)
        print(request.url)

        print(dir(request))
        return self.user_strategy if "user" in request.url else self.app_strategy

    def __call__(self, request):
        request.headers.update(self.pick_strategy(request).get_header())
        return request


def local_auth_callback(login_url: str):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            if "error" in params:
                msg = f"Authorization failed: {params.get('error_description')}"
            else:
                msg = "Authorization successful.\nYou may close this page."
            self._respond(msg)
            self.server._response_path = self.path  # HACK: save request path
            self.server.shutdown()

        def _respond(self, message, status=200):
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html><body><pre>{message}</pre></body></html>".encode())

    webbrowser.open(login_url)
    with ThreadingHTTPServer(("", 3000), Handler) as httpd:
        print("Waiting for authorization callback...")
        httpd.serve_forever(poll_interval=0.1)
        return httpd._response_path


class RequestsHttpClient:
    post = staticmethod(requests.post)


def main():
    """Main flow"""
    print("=" * 50)
    print("OAuth 2.0 Authorization Flow")
    print("=" * 50)

    CLIENT_ID = environ.get("TIDAL_CLIENT_ID", "test")
    CLIENT_SECRET = environ.get("TIDAL_CLIENT_SECRET", "secret")

    oauth = OAuth2Helper(
        app="liszted",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        token_endpoint="https://auth.tidal.com/v1/oauth2/token",
        authorization_endpoint="https://login.tidal.com/authorize",
        redirect_uri="http://localhost:3000/callback",
        scope=(
            "collection.read",
            "collection.write",
            "entitlements.read",
            "playback",
            "playlists.read",
            "playlists.write",
            "recommendations.read",
            "search.read",
            "search.write",
            "user.read",
        ),
        auth_response_handler=local_auth_callback,
        http_client=RequestsHttpClient(),
    )

    with requests.Session() as session:
        session.auth = oauth
        response = session.get("https://openapi.tidal.com/v2/users/me")
        response.raise_for_status()
        print(response.json())


if __name__ == "__main__":
    main()
