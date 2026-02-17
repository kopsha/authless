import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from os import environ
from urllib.parse import parse_qs, urlparse

import requests

from .helper import OAuth2Helper


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


def main():
    """Main flow"""
    print("=" * 50)
    print("OAuth 2.0 Authorization Flow")
    print("=" * 50)

    CLIENT_ID = environ.get("TIDAL_CLIENT_ID", "test")
    CLIENT_SECRET = environ.get("TIDAL_CLIENT_SECRET", "secret")

    oauth = OAuth2Helper(
        app="token-trial",
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
        http_client=requests.Session(),
    )

    with requests.Session() as session:
        session.auth = oauth
        response = session.get("https://openapi.tidal.com/v2/users/me")
        response.raise_for_status()
        print(response.json())


if __name__ == "__main__":
    main()
