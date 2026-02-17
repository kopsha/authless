
# OAuth2Helper

`OAuth2Helper` is a small wrapper around the two most common OAuth 2.0 flows:

- **Authorization Code + PKCE** (for user‑level access)  
- **Client Credentials** (for app‑level access)

It plugs directly into `requests.Session` and automatically attaches the correct
`Authorization` header, refreshes tokens, and persists them.

This guide shows only what you need to start using it.


## Quickstart

### Provide a callback handler

This function opens the browser and waits for the redirect to your local server:

```python
def local_auth_callback(login_url: str):
    # e.g. opens browser and waits for http://localhost:3000/callback
    ...
```

Your OAuth app must have this redirect URI registered.


### Create the OAuth2Helper instance

```python
from helper import OAuth2Helper
import requests

oauth = OAuth2Helper(
    app="my-app",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    token_endpoint="https://example.com/oauth2/token",
    authorization_endpoint="https://example.com/oauth2/authorize",
    redirect_uri="http://localhost:3000/callback",
    scope=("read", "write", "profile"),
    auth_response_handler=local_auth_callback,
    http_client=requests.Session(),
)
```

Everything else (PKCE, refresh, persistence) is handled internally.


### Use it with `requests`

```python
with requests.Session() as session:
    session.auth = oauth
    r = session.get("https://api.example.com/v1/me")
    print(r.json())
```

On the first request that requires user authentication:

- Your browser opens  
- You log in  
- Tokens are stored locally  
- Future calls reuse and refresh them automatically  

---

## Strategy selection

The helper chooses between:

- **User token** (Authorization Code flow)  
- **App token** (Client Credentials flow)

based on simple substring matching in the request URL.

Default:

```python
user_uri_patterns = ("/user",)
```

You can change this by editing `pick_strategy()`.



## Token persistence

Tokens are stored on disk using the `PersistentTokens` class. Each token set (user
token and app token) is stored as a JSON file under:
```
~/.local/share/<app name>/<app | user>_token.json
```

The directory is created automatically on first use. The class keeps fields such
as `access_token`, `refresh_token`, `expires_at`, and others in memory, and updates
the JSON file whenever new token data is written. On startup, the helper loads
the file if it exists, checks whether the token is expired, and refreshes it when
needed. This makes the authentication flow run only once—subsequent runs reuse
the stored tokens.

