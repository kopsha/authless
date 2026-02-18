import hashlib
from abc import ABC, abstractmethod
from base64 import b64encode, urlsafe_b64encode
from collections.abc import Callable
from secrets import token_urlsafe
from typing import Any, Protocol
from urllib.parse import parse_qs, urlencode, urlparse

from requests import PreparedRequest
from requests.auth import AuthBase

from .tokens import PersistentTokens


class AnyHttpClient(Protocol):
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
        client_secret: str,
        token_endpoint: str,
        authorization_endpoint: str,
        redirect_uri: str,
        scope: tuple[str, ...],
        auth_response_handler: Callable,
        http_client: AnyHttpClient,
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

    def pick_strategy(self, uri: str):
        # TODO: strategy selection should be done by the user
        user_uri_patterns = ("/user",)
        return (
            self.user_strategy
            if any(p in uri for p in user_uri_patterns)
            else self.app_strategy
        )

    def __call__(self, request: PreparedRequest):
        strategy = self.pick_strategy(request.url or "")
        request.headers.update(strategy.get_header())
        return request
