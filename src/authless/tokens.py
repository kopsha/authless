import json
from dataclasses import InitVar, asdict, dataclass
from pathlib import Path
from time import time
from typing import ClassVar


@dataclass
class PersistentTokens:
    CACHE_DIR: ClassVar[Path] = Path.home() / ".local" / "share"
    app: InitVar[str]
    named: InitVar[str]

    refresh_token: str = ""
    access_token: str = ""
    scope: str = ""
    token_type: str = ""
    expires_at: int = 0
    user_id: int = 0

    def __post_init__(self, app: str, filename: str):
        app_cache = self.CACHE_DIR / app
        app_cache.mkdir(exist_ok=True, parents=True)
        self.filepath = app_cache / f"{filename}.json"

    def _update(self, data):
        for key, value in data.items():
            if key == "expires_in":
                key = "expires_at"
                value += int(time()) - 1
            setattr(self, key, value)

    def read(self):
        try:
            data = json.loads(self.filepath.read_text())
            self._update(data)
        except FileNotFoundError:
            pass

    def write(self, data):
        self._update(data)
        self.filepath.write_text(json.dumps(asdict(self), indent=4))
        self.filepath.chmod(0o600)

    def is_expired(self, now=None):
        now = now or int(time())
        return now > self.expires_at

    def is_empty(self):
        return not self.access_token

    def as_header(self):
        return dict(Authorization=f"{self.token_type} {self.access_token}")
