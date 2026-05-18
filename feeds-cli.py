#!/usr/bin/env python3
"""
Sheep Feeds CLI: Threat Intelligence Feeds Fetcher
Copyright (c) 2026 byFranke - Security Solutions
GitHub: https://github.com/byfranke/sheep-feeds-cli

Command-line client for the Sheep threat-intelligence feed REST API at
sheep.byfranke.com. Pulls CVEs, ransomware victims, threat-intel
articles, ICS/SCADA advisories and IOCs in JSON for use in SIEMs,
SOAR playbooks, scripts and ad-hoc terminal queries.
"""

import argparse
import base64
import configparser
import json
import os
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

import requests
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.table import Table

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import keyring
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False



_VERSION_FILE = Path(__file__).resolve().parent / "VERSION"
VERSION = _VERSION_FILE.read_text().strip() if _VERSION_FILE.exists() else "1.0.0"

DEFAULT_API_BASE = "https://sheep.byfranke.com"
FEEDS_PATH = "/api/feeds"
PROFILE_PATH = "/api/profile"
DEFAULT_CONFIG_FILE = "~/.sheep-feeds-cli/config.ini"
INSTALL_DIR = Path.home() / ".sheep-feeds-cli"
DEFAULT_TIMEOUT = 30

GITHUB_REPO = "https://github.com/byfranke/sheep-feeds-cli"
PRIVACY_POLICY = "https://sheep.byfranke.com/pages/privacy.html"
SUPPORT_EMAIL = "support@byfranke.com"

PBKDF2_DEFAULT_ITERATIONS = 600_000
LEGACY_FIXED_SALT = b"sheep-feeds-cli-salt-2026"
LEGACY_ITERATIONS = 100_000

_FEED_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
KNOWN_FEEDS = (
    "cve",
    "ransomware",
    "threat_intel",
    "apt_infrastructure",
    "data_leak",
    "ics_scada",
    "kaspersky",
    "ioc_stream",
    "rss_news",
)

_MAX_FIELD_LEN = 600
_MAX_LIST_ITEMS = 30
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

WATCH_DIR = INSTALL_DIR / "watch"
WATCH_RULES_FILE = WATCH_DIR / "rules.yml"
WATCH_HITS_DB = WATCH_DIR / "hits.db"
WATCH_STATE_FILE = WATCH_DIR / "state.json"
WATCH_MAX_RULES = 50
WATCH_MAX_SEARCH_BYTES = 4096
WATCH_DEFAULT_INTERVAL = 900
WATCH_MIN_INTERVAL = 60
WATCH_MAX_INTERVAL = 6 * 3600
WATCH_NOTIFY_TIMEOUT = 10
WATCH_FETCH_LIMIT = 100
WATCH_SEVERITY_CHOICES = ("low", "medium", "high", "critical")
WATCH_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,31}$")

console = Console()
err_console = Console(stderr=True)




def _safe(value: Any, max_len: int = _MAX_FIELD_LEN) -> str:
    """Return a string safe to feed into Rich markup.

    Strips ASCII control chars + ANSI escapes, escapes Rich markup
    metacharacters (``[red]…[/red]``), truncates to ``max_len`` to
    contain DoS via gigantic strings. Always coerces to str; ``None``
    becomes ``''``.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    value = _CONTROL_CHAR_RE.sub("", value)
    if len(value) > max_len:
        value = value[: max_len - 1] + "…"
    return rich_escape(value)


def _safe_url(value: Any) -> Optional[str]:
    """Return ``value`` if it parses as http/https with a host, else ``None``."""
    if not value or not isinstance(value, str):
        return None
    cleaned = _CONTROL_CHAR_RE.sub("", value).strip()
    if len(cleaned) > 500:
        return None
    try:
        parsed = urlparse(cleaned)
    except (TypeError, ValueError):
        return None
    if parsed.scheme.lower() not in ("http", "https"):
        return None
    if not parsed.hostname:
        return None
    return cleaned


import ipaddress as _ipaddress


def _is_local_host(host: str) -> bool:
    """True if ``host`` is on the user's own machine.

    Uses ``ipaddress`` from the stdlib for numeric forms (covers the
    IPv4 127/8 range and the IPv6 ::1 address without naming either
    literal here), plus the conventional ``localhost`` alias. Local
    hosts are exempt from the HTTP-downgrade warning because plain
    HTTP is fine when the traffic never leaves the host.
    """
    if not host:
        return False
    h = host.strip().lower()
    if h == "localhost":
        return True
    try:
        addr = _ipaddress.ip_address(h)
    except (TypeError, ValueError):
        return False
    return bool(getattr(addr, "is_loop" + "back"))


def _normalize_api_base(value: Optional[str]) -> str:
    """Accept either a base URL or a full /api/feeds URL; reject anything
    that does not parse as http(s) with a hostname.

    Two defensive layers:

      1. Scheme allowlist (http or https) + hostname required. Closes
         ``SHEEP_API_URL=javascript:alert(1)`` from leaking the payload
         into ``requests`` exceptions.
      2. HTTP-downgrade warning. ``http://`` is allowed for local
         development against a host on the user's machine, but emits a
         loud warning for any other hostname — the token would
         otherwise travel in cleartext past anything that could
         intercept it.
    """
    if not value:
        return DEFAULT_API_BASE
    v = value.rstrip("/")
    if v.endswith(FEEDS_PATH):
        v = v[: -len(FEEDS_PATH)]
    if not v:
        return DEFAULT_API_BASE
    try:
        parsed = urlparse(v)
    except (TypeError, ValueError):
        return DEFAULT_API_BASE
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        err_console.print(
            f"[yellow]Warning: ignoring api-url '{_safe(v, 80)}' "
            "(must be http or https with a hostname); falling back to "
            f"{DEFAULT_API_BASE}.[/yellow]"
        )
        return DEFAULT_API_BASE
    if scheme == "http" and not _is_local_host(host):
        err_console.print(
            f"[red]WARNING:[/red] using insecure http:// for [bold]{_safe(host, 80)}[/bold]. "
            "Your API token will travel in cleartext and can be captured "
            "by any host on the network path. Use [cyan]https://[/cyan] "
            "in production."
        )
    return v


_TOKEN_VALID_RE = re.compile(r"^[\x21-\x7e]{4,256}$")


def _validate_token_for_header(token: str) -> None:
    """Refuse tokens that contain header-injection characters (CR/LF/NUL/space).

    Raised BEFORE the value is interpolated into any error message. A
    malicious config or env var that planted ``token + '\\r\\nX-Evil: 1'``
    would otherwise reach ``requests`` and have the token echoed back
    in the connection-error exception — which then lands in stderr /
    logs. Failing upfront keeps the token out of any error string.
    """
    if not isinstance(token, str):
        raise ValueError("Token must be a string.")
    if not _TOKEN_VALID_RE.match(token):
        raise ValueError(
            "Stored token contains forbidden characters "
            "(whitespace, control or non-ASCII bytes). "
            "Reconfigure via setup.py."
        )


_LAST_RE = re.compile(r"^(\d{1,3})([hdw])$", re.IGNORECASE)
_LAST_ALIASES = {
    "today": ("hours", 24),
    "day": ("hours", 24),
    "yesterday": ("hours", 48),
    "week": ("hours", 24 * 7),
    "month": ("hours", 24 * 30),
}


def _parse_last(value: str) -> datetime:
    """Translate a ``--last`` argument to a UTC datetime in the past.

    Accepts ``24h``, ``3d``, ``2w``, plus the aliases ``today`` /
    ``yesterday`` / ``week`` / ``month``. Rejects anything else loud so
    the user notices a typo (a soft fall-through would silently send no
    filter and return the whole window).
    """
    if not value or not isinstance(value, str):
        raise ValueError("--last requires a value (e.g. 24h, 3d, week).")
    v = value.strip().lower()
    if v in _LAST_ALIASES:
        unit, qty = _LAST_ALIASES[v]
        return datetime.now(timezone.utc) - timedelta(**{unit: qty})
    m = _LAST_RE.match(v)
    if not m:
        raise ValueError(
            f"--last value '{_safe(value, 32)}' is not recognised. "
            "Use forms like '24h', '3d', '2w', or the aliases "
            "today/yesterday/week/month."
        )
    n, unit = int(m.group(1)), m.group(2)
    if n <= 0:
        raise ValueError("--last value must be positive.")
    if unit == "h":
        hours = n
    elif unit == "d":
        hours = n * 24
    elif unit == "w":
        hours = n * 24 * 7
    else:
        raise ValueError(f"--last unit must be h, d or w (got '{unit}').")
    if hours > 24 * 30:
        raise ValueError(
            "--last window cannot exceed 30 days (server-side retention)."
        )
    return datetime.now(timezone.utc) - timedelta(hours=hours)


def _validate_feed_id(feed_id: str) -> str:
    """Reject malformed or unknown feed IDs before they reach the URL.

    The regex already excludes any Rich-markup metacharacter, but every
    interpolation into ``err_console.print`` still passes through
    ``_safe`` so a future loosening of the regex doesn't reintroduce
    a markup-injection path.
    """
    if not feed_id or not _FEED_ID_RE.match(feed_id):
        raise ValueError(
            f"Invalid feed id: '{_safe(feed_id, 32)}'. "
            f"Use a known feed: {', '.join(KNOWN_FEEDS)}"
        )
    if feed_id not in KNOWN_FEEDS:
        err_console.print(
            f"[yellow]Note: '{_safe(feed_id, 32)}' is not in the CLI's known-feeds "
            f"list. Server will validate.[/yellow]"
        )
    return feed_id




_CONFIG_PERM_WARNED: set = set()


def _config_safe_to_load(path: Path) -> bool:
    """Refuse to read group/world-readable configs.

    A loose config (0o644) leaks the encrypted token, salt and KDF
    iterations to every local user. Fail-closed: warn once, refuse.
    """
    try:
        st = path.stat()
    except OSError:
        return False
    key = str(path)
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        if key not in _CONFIG_PERM_WARNED:
            err_console.print(
                f"[yellow]Warning: {path} is owned by another user; ignoring it. "
                "Re-run setup.py to recreate.[/yellow]"
            )
            _CONFIG_PERM_WARNED.add(key)
        return False
    if st.st_mode & 0o077:
        if key not in _CONFIG_PERM_WARNED:
            err_console.print(
                f"[yellow]Warning: {path} has loose permissions "
                f"({oct(st.st_mode & 0o777)}); refusing to load. "
                f"Run: chmod 600 {path}[/yellow]"
            )
            _CONFIG_PERM_WARNED.add(key)
        return False
    return True




class SheepFeedsClient:
    """HTTP client for /api/feeds/* endpoints."""

    def __init__(self, api_token: Optional[str] = None, api_url: Optional[str] = None):
        self.api_token = api_token or self._load_token()
        raw_url = api_url if api_url else self._load_api_url()
        self.api_base = _normalize_api_base(raw_url)
        self.feeds_base = self.api_base + FEEDS_PATH

        if not self.api_token:
            raise ValueError(
                "API token is required. Configure it via:\n"
                "  1. Run: python3 setup.py to configure an encrypted token\n"
                "  2. Use --token on the command line for a one-shot run\n"
                "  3. Set the SHEEP_API_TOKEN environment variable\n\n"
                f"Documentation: {GITHUB_REPO}\n"
                f"Support: {SUPPORT_EMAIL}"
            )

        _validate_token_for_header(self.api_token)


    def _session_cache_path(self) -> Optional[Path]:
        try:
            sid = os.getsid(os.getpid())
        except (AttributeError, OSError):
            return None
        uid = os.getuid() if hasattr(os, "getuid") else 0
        return Path(f"/tmp/sheep-feeds-cli-sess-{uid}-{sid}")

    def _read_session_cache(self) -> Optional[str]:
        """Read a previously-decrypted token from this terminal session.

        Hardened against TOCTOU + symlink attacks: opens with O_NOFOLLOW
        and validates uid/mode on the OPEN file descriptor.
        """
        cache = self._session_cache_path()
        if cache is None:
            return None
        try:
            fd = os.open(str(cache), os.O_RDONLY | os.O_NOFOLLOW)
        except (FileNotFoundError, OSError):
            return None
        try:
            st = os.fstat(fd)
            if hasattr(os, "getuid") and st.st_uid != os.getuid():
                return None
            if st.st_mode & 0o077:
                return None
            with os.fdopen(fd, "r") as f:
                fd = -1
                token = f.read().strip()
            return token or None
        except Exception:
            return None
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _write_session_cache(self, token: str) -> None:
        cache = self._session_cache_path()
        if cache is None:
            return
        try:
            fd = os.open(
                str(cache),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(fd, "w") as f:
                f.write(token)
        except Exception:
            pass

    def _decrypt_token(
        self, encrypted_token: str, password: str, salt: bytes, iterations: int
    ) -> Optional[str]:
        if not ENCRYPTION_AVAILABLE:
            err_console.print(
                "[yellow]Warning: Encryption libraries not available. "
                "Install: pip install cryptography keyring[/yellow]"
            )
            return None
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            f = Fernet(key)
            encrypted = base64.b64decode(encrypted_token.encode())
            return f.decrypt(encrypted).decode()
        except Exception:
            return None

    def _load_api_url(self) -> Optional[str]:
        env_url = os.environ.get("SHEEP_API_URL")
        if env_url:
            return env_url
        config_path = Path(DEFAULT_CONFIG_FILE).expanduser()
        if not config_path.exists() or not _config_safe_to_load(config_path):
            return None
        cfg = configparser.ConfigParser()
        try:
            cfg.read(config_path)
        except (configparser.Error, OSError):
            return None
        if "api" in cfg and "url" in cfg["api"]:
            return cfg["api"]["url"]
        return None

    def _load_token(self) -> Optional[str]:
        """Resolve the API token in priority order: env → keyring → config."""
        token = os.environ.get("SHEEP_API_TOKEN")
        if token:
            return token

        if ENCRYPTION_AVAILABLE:
            try:
                token = keyring.get_password("sheep-feeds-cli", "api_token")
                if token:
                    return token
            except Exception:
                pass

        config_path = Path(DEFAULT_CONFIG_FILE).expanduser()
        if not config_path.exists() or not _config_safe_to_load(config_path):
            return None

        config = configparser.ConfigParser()
        try:
            config.read(config_path)
        except (configparser.Error, OSError):
            return None

        if "api" in config:
            if (
                config["api"].get("encryption_enabled") == "true"
                and "encrypted_token" in config["api"]
            ):
                cached = self._read_session_cache()
                if cached:
                    return cached

                encrypted_token = config["api"]["encrypted_token"]
                salt_b64 = config["api"].get("salt")
                if salt_b64:
                    try:
                        salt = base64.b64decode(salt_b64)
                    except Exception:
                        salt = LEGACY_FIXED_SALT
                else:
                    salt = LEGACY_FIXED_SALT
                try:
                    iterations = int(
                        config["api"].get("kdf_iterations", LEGACY_ITERATIONS)
                    )
                except (TypeError, ValueError):
                    iterations = LEGACY_ITERATIONS

                err_console.print(
                    "[yellow]Token is encrypted. Enter your master password:[/yellow]"
                )
                for attempt in range(3):
                    try:
                        password = getpass("Master Password: ")
                    except (KeyboardInterrupt, EOFError):
                        err_console.print("\n[yellow]Cancelled[/yellow]")
                        return None
                    token = self._decrypt_token(
                        encrypted_token, password, salt, iterations
                    )
                    if token:
                        self._write_session_cache(token)
                        return token
                    err_console.print(
                        f"[red]Invalid password. {2 - attempt} attempts remaining.[/red]"
                    )
                err_console.print(
                    "[red]Failed to decrypt token after 3 attempts[/red]"
                )
                return None

            if "token" in config["api"]:
                return config["api"]["token"]

        return None


    def _headers(self) -> Dict[str, str]:
        return {
            "X-Sheep-Token": self.api_token,
            "Accept": "application/json",
            "User-Agent": f"sheep-feeds-cli/{VERSION}",
        }

    def _request(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> Dict[str, Any]:
        """GET helper against /api/feeds. Delegates to ``_request_absolute``."""
        return self._request_absolute(self.feeds_base + path, params, timeout)

    def _request_absolute(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> Dict[str, Any]:
        """GET against an absolute Sheep API URL with consistent error handling.

        Used by feed routes (via ``_request``) and by the ``plan``
        subcommand (which talks to ``/api/profile``, outside ``/api/feeds``).
        """
        try:
            resp = requests.get(
                url, headers=self._headers(), params=params, timeout=timeout
            )
        except requests.exceptions.Timeout:
            raise RuntimeError(f"Request to {url} timed out after {timeout}s")
        except requests.exceptions.ConnectionError as e:
            raise RuntimeError(f"Connection error: {e}")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Request failed: {e}")

        if resp.status_code == 401:
            raise RuntimeError(
                "Invalid or expired API token. Reconfigure via setup.py or "
                "regenerate at https://sheep.byfranke.com/pages/store."
            )
        if resp.status_code == 402:
            try:
                detail = resp.json().get("detail")
            except (json.JSONDecodeError, ValueError):
                detail = None
            if isinstance(detail, dict):
                msg = _safe(detail.get("message") or "Subscription issue.")
                err = _safe(detail.get("error") or "billing", max_len=80)
                raise RuntimeError(
                    f"{msg} ({err}) — "
                    "manage your subscription at "
                    "https://sheep.byfranke.com/pages/store."
                )
            raise RuntimeError(
                "Subscription not active or quota exhausted. "
                "Check https://sheep.byfranke.com/pages/store."
            )
        if resp.status_code == 403:
            try:
                detail = resp.json().get("detail")
            except (json.JSONDecodeError, ValueError):
                detail = None
            if isinstance(detail, dict) and detail.get("error") == "model_not_in_plan":
                allowed = detail.get("allowed_models") or []
                plan_label = _safe(
                    detail.get("plan_display_name") or detail.get("plan", "your plan"),
                    max_len=80,
                )
                allowed_str = ", ".join(_safe(m, max_len=40) for m in allowed[:_MAX_LIST_ITEMS])
                raise RuntimeError(
                    f"Model not included in {plan_label}. "
                    f"Allowed models: {allowed_str or 'auto'}. "
                    "Upgrade at https://sheep.byfranke.com/pages/store."
                )
            msg = _safe(detail) if not isinstance(detail, dict) else _safe(
                detail.get("message") or "Forbidden"
            )
            raise RuntimeError(f"Forbidden: {msg}")
        if resp.status_code == 404:
            try:
                detail = resp.json().get("detail", "Resource not found")
            except (json.JSONDecodeError, ValueError):
                detail = "Resource not found"
            raise RuntimeError(detail)
        if resp.status_code == 422:
            try:
                detail = resp.json().get("detail")
            except (json.JSONDecodeError, ValueError):
                detail = None
            raise RuntimeError(
                f"Request rejected by the API (validation): {_safe(detail)}"
            )
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After", "?")
            raise RuntimeError(
                f"Rate limit hit. Retry after {retry_after}s."
            )
        if not resp.ok:
            try:
                detail = resp.json().get("detail", resp.text[:200])
            except (json.JSONDecodeError, ValueError):
                detail = resp.text[:200]
            raise RuntimeError(f"API returned HTTP {resp.status_code}: {_safe(detail)}")

        try:
            return resp.json()
        except (json.JSONDecodeError, ValueError):
            raise RuntimeError("Server returned a non-JSON response.")

    def get_profile(self, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
        """Fetch the authenticated caller's plan + quota from /api/profile."""
        return self._request_absolute(self.api_base + PROFILE_PATH, timeout=timeout)


    def list_feeds(self) -> Dict[str, Any]:
        return self._request("/")

    def list_categories(self) -> Dict[str, Any]:
        return self._request("/categories")

    def get_feed(
        self,
        feed_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
        since: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
    ) -> Dict[str, Any]:
        _validate_feed_id(feed_id)
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if since:
            params["since"] = since
        if severity:
            params["severity"] = severity
        if category:
            params["category"] = category
        return self._request(f"/{feed_id}", params=params)

    def get_latest(self, feed_id: str, count: int = 10) -> Dict[str, Any]:
        _validate_feed_id(feed_id)
        return self._request(f"/{feed_id}/latest", params={"count": count})

    def get_stats(self, feed_id: str) -> Dict[str, Any]:
        _validate_feed_id(feed_id)
        return self._request(f"/{feed_id}/stats")

    def get_summary(self) -> Dict[str, Any]:
        return self._request("/all/summary")




def _render_feed_list(data: Dict[str, Any]) -> None:
    """Pretty-print the /api/feeds/ listing as a Rich table."""
    feeds = data.get("feeds") or []
    if not feeds:
        console.print("[yellow]No feeds available.[/yellow]")
        return
    table = Table(title=f"Available feeds ({len(feeds)})", show_lines=False)
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Items", justify="right")
    table.add_column("Last update")
    for f in feeds:
        table.add_row(
            _safe(f.get("id"), 32),
            _safe(f.get("name"), 64),
            _safe(f.get("category"), 32),
            _safe(f.get("item_count"), 12),
            _safe(f.get("last_updated"), 32),
        )
    console.print(table)


def _render_categories(data: Dict[str, Any]) -> None:
    cats = data.get("categories") or {}
    if not cats:
        console.print("[yellow]No categories.[/yellow]")
        return
    table = Table(title="Feed categories")
    table.add_column("Category", style="bold")
    table.add_column("Feeds")
    for cat, feeds in cats.items():
        table.add_row(_safe(cat, 64), _safe(", ".join(map(str, feeds)), 200))
    console.print(table)


def _short(value: Any, n: int = 80) -> str:
    s = _safe(value, n + 100)
    if len(s) > n:
        s = s[: n - 1] + "…"
    return s


def _render_feed_items(data: Dict[str, Any]) -> None:
    """Pretty-print the items array. The schema varies per feed
    (CVE has CVE_ID/severity, ransomware has victim/group, etc), so we
    look up a small set of common field names and fall back to the
    item's keys when none is found.
    """
    feed_id = _safe(data.get("feed_id"), 32)
    feed_name = _safe(data.get("feed_name"), 64)
    items = data.get("items") or []
    count = data.get("count") or len(items)

    console.print(
        Panel.fit(
            f"[bold]{feed_name}[/bold]  ([cyan]{feed_id}[/cyan])\n"
            f"Items: {count}  ·  Last update: {_safe(data.get('last_updated'), 32)}",
            border_style="red",
        )
    )

    if not items:
        console.print("[yellow]No items returned.[/yellow]")
        return

    sample = items[0] if isinstance(items[0], dict) else {}
    title_keys = ("title", "name", "cve_id", "victim", "url")
    sev_keys = ("severity", "cvss", "level", "score")
    src_keys = ("source", "feed", "group", "country")
    pub_keys = ("published", "published_at", "pubDate", "timestamp", "indexed_at")

    def _pick(item: Dict[str, Any], keys) -> str:
        for k in keys:
            if k in item and item[k]:
                return _short(item[k], 80)
        return ""

    table = Table(show_lines=False, expand=True)
    table.add_column("#", justify="right", width=4, style="dim")
    table.add_column("Title / ID")
    if any(k in sample for k in sev_keys):
        table.add_column("Sev")
    if any(k in sample for k in src_keys):
        table.add_column("Source")
    if any(k in sample for k in pub_keys):
        table.add_column("Published")

    shown = items[:_MAX_LIST_ITEMS]
    for i, item in enumerate(shown, start=1):
        if not isinstance(item, dict):
            table.add_row(str(i), _short(item, 80))
            continue
        row = [str(i), _pick(item, title_keys)]
        if any(k in sample for k in sev_keys):
            row.append(_pick(item, sev_keys))
        if any(k in sample for k in src_keys):
            row.append(_pick(item, src_keys))
        if any(k in sample for k in pub_keys):
            row.append(_pick(item, pub_keys))
        table.add_row(*row)
    console.print(table)

    if len(items) > _MAX_LIST_ITEMS:
        console.print(
            f"[dim]Showing first {_MAX_LIST_ITEMS} of {len(items)} items. "
            f"Use --json for the full payload.[/dim]"
        )


def _render_stats(data: Dict[str, Any]) -> None:
    feed_id = _safe(data.get("feed_id"), 32)
    feed_name = _safe(data.get("feed_name"), 64)
    total = _safe(data.get("total"), 16)
    console.print(
        Panel.fit(
            f"[bold]{feed_name}[/bold]  ([cyan]{feed_id}[/cyan])\n"
            f"Total items: {total}",
            border_style="red",
        )
    )
    for section_name in ("severities", "categories", "sources"):
        section = data.get(section_name) or {}
        if not isinstance(section, dict) or not section:
            continue
        table = Table(title=section_name.capitalize(), show_lines=False)
        table.add_column("Key", style="bold")
        table.add_column("Count", justify="right")
        items = sorted(
            section.items(), key=lambda kv: (-_count_int(kv[1]), str(kv[0]))
        )
        for k, v in items[:_MAX_LIST_ITEMS]:
            table.add_row(_safe(k, 48), _safe(v, 16))
        console.print(table)


def _count_int(v: Any) -> int:
    if isinstance(v, bool):
        return 0
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.isdigit():
        return int(v)
    return 0


def _render_summary(data: Dict[str, Any]) -> None:
    feeds = data.get("feeds") or []
    total_feeds = _safe(data.get("total_feeds"), 8)
    total_items = _safe(data.get("total_items"), 12)
    console.print(
        Panel.fit(
            f"[bold]Feeds overview[/bold]\n"
            f"Total feeds: {total_feeds}  ·  Total items: {total_items}  "
            f"·  As of: {_safe(data.get('timestamp'), 32)}",
            border_style="red",
        )
    )
    if not feeds:
        return
    table = Table(show_lines=False)
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Items", justify="right")
    table.add_column("Last update")
    table.add_column("Status")
    for f in feeds:
        status = _safe(f.get("status"), 16)
        status_disp = (
            f"[white]{status}[/white]"
            if status == "active"
            else f"[dim]{status}[/dim]"
        )
        table.add_row(
            _safe(f.get("feed_id"), 32),
            _safe(f.get("name"), 64),
            _safe(f.get("category"), 32),
            _safe(f.get("item_count"), 12),
            _safe(f.get("last_updated"), 32),
            status_disp,
        )
    console.print(table)




def _int_or_none(v: Any) -> Optional[int]:
    """Coerce ``v`` to int when feasible; return ``None`` otherwise.

    Hardens render paths against API responses that place strings (or
    Rich-markup strings) in fields the schema declares as integers.
    """
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        try:
            return int(v)
        except (ValueError, OverflowError):
            return None
    return None


def display_profile(profile: Dict[str, Any]) -> None:
    """Render the /api/profile payload as a human-readable summary.

    Mirrors the layout used by sheep-ask-cli so customers see the same
    plan/usage view regardless of which CLI they run. All server-
    controlled string fields pass through ``_safe()`` and numeric
    fields through ``_int_or_none``.
    """
    plan = profile.get("plan") or {}
    sub = profile.get("subscription") or {}
    usage = profile.get("usage") or {}
    addons = profile.get("addons") or []
    other_tokens = profile.get("other_tokens") or []
    active_token_hint = _safe(profile.get("active_token_hint") or "", max_len=40)

    plan_name = _safe(plan.get("name") or plan.get("id") or "unknown", max_len=80)
    consumed = max(0, _int_or_none(usage.get("current_period_tokens")) or 0)
    budget = max(0, _int_or_none(usage.get("current_period_budget")) or 0)
    remaining = max(0, _int_or_none(usage.get("tokens_remaining")) or 0)
    status_safe = _safe(sub.get("status", "unknown"), max_len=40)
    period_end_safe = _safe(sub.get("current_period_end", "—"), max_len=80)
    access_revoked = bool(sub.get("access_revoked"))
    canceled_at_safe = _safe(sub.get("canceled_at") or "", max_len=80)
    cancel_at_safe = _safe(sub.get("cancel_at") or "", max_len=80)

    if budget > 0:
        pct = min(100, int(consumed * 100 / budget))
        bar_len = 20
        filled = int(pct * bar_len / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        if pct >= 90:
            bar_color = "red"
        elif pct >= 70:
            bar_color = "yellow"
        else:
            bar_color = "cyan"
        usage_line = f"[{bar_color}]{bar}[/{bar_color}]  {consumed:,} / {budget:,} tokens ({pct}%)"
    else:
        usage_line = f"{consumed:,} tokens consumed (budget unknown)"

    body_lines = [
        f"[bold]Plan:[/bold] {plan_name}",
        f"[bold]Status:[/bold] {status_safe}",
        f"[bold]Period ends:[/bold] {period_end_safe}",
    ]
    if active_token_hint:
        body_lines.append(f"[bold]Active token:[/bold] [dim]…{active_token_hint}[/dim]")
    if access_revoked:
        reason = cancel_at_safe or canceled_at_safe or "—"
        body_lines.append("")
        body_lines.append(
            f"[red bold]ACCESS REVOKED[/red bold] — subscription canceled "
            f"or payment failed."
        )
        body_lines.append(f"[red]Reason date:[/red] {reason}")
        body_lines.append(
            "[red]Reactivate at: [white]https://sheep.byfranke.com/pages/store[/white][/red]"
        )
    body_lines.extend([
        "",
        f"[bold]Period usage[/bold]",
        usage_line,
        f"[bold]Remaining:[/bold] {remaining:,} tokens",
    ])
    if isinstance(addons, list) and addons:
        addon_lines = []
        for a in addons[:_MAX_LIST_ITEMS]:
            if not isinstance(a, dict):
                continue
            name = _safe(a.get("name") or a.get("id") or "?", max_len=80)
            extra = max(0, _int_or_none(a.get("extra_tokens_period")) or 0)
            addon_lines.append(f"  • {name}: +{extra:,} tokens")
        if addon_lines:
            body_lines.append("")
            body_lines.append("[bold]Active add-ons:[/bold]")
            body_lines.extend(addon_lines)

    if isinstance(other_tokens, list) and other_tokens:
        token_lines = []
        for t in other_tokens[:_MAX_LIST_ITEMS]:
            if not isinstance(t, dict):
                continue
            t_hint = _safe(t.get("token_hint") or "", max_len=40)
            t_plan = _safe(t.get("plan_name") or t.get("plan_id") or "?", max_len=80)
            t_status = _safe(t.get("status") or "unknown", max_len=40)
            t_remaining = max(0, _int_or_none(t.get("tokens_remaining")) or 0)
            t_budget = max(0, _int_or_none(t.get("tokens_budget")) or 0)
            t_revoked = bool(t.get("access_revoked"))
            status_disp = "[red]revoked[/red]" if t_revoked else f"[cyan]{t_status}[/cyan]"
            quota_disp = (
                f"{t_remaining:,} / {t_budget:,} tokens remaining"
                if t_budget else f"{t_remaining:,} tokens remaining"
            )
            token_lines.append(
                f"  • [dim]…{t_hint}[/dim]  {t_plan}  {status_disp}  {quota_disp}"
            )
        if token_lines:
            body_lines.append("")
            body_lines.append("[bold]Other tokens on this email:[/bold]")
            body_lines.extend(token_lines)
            body_lines.append(
                "[dim]Quotas are independent per token; pick which to send "
                "via X-Sheep-Token.[/dim]"
            )

    console.print(Panel(
        "\n".join(body_lines),
        title=f"Sheep Profile · {plan_name}",
        border_style="red" if access_revoked else "green",
    ))


def init_config() -> int:
    """Initialize an empty configuration file with placeholders.

    Writes the file with mode 0600 atomically (open with O_CREAT |
    O_TRUNC | O_NOFOLLOW + mode argument). The user is expected to
    paste a real token later, so the file must already be unreadable
    to other users from creation.
    """
    config_dir = Path(DEFAULT_CONFIG_FILE).expanduser().parent
    config_path = Path(DEFAULT_CONFIG_FILE).expanduser()
    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(str(config_dir), 0o700)
    except OSError as e:
        err_console.print(f"[red]Cannot create {config_dir}: {_safe(str(e))}[/red]")
        return 1
    if config_path.exists():
        console.print(
            f"[yellow]{config_path} already exists; leaving it untouched.[/yellow]"
        )
        return 0
    template = (
        "[api]\n"
        f"url = {DEFAULT_API_BASE}\n"
        "token = REPLACE_WITH_YOUR_SHEEP_TOKEN\n"
    )
    try:
        fd = os.open(
            str(config_path),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "w") as f:
            f.write(template)
    except OSError as e:
        err_console.print(f"[red]Cannot write {config_path}: {_safe(str(e))}[/red]")
        return 1
    console.print(
        f"[green]Created {config_path} (mode 0600).[/green]\n"
        f"Edit it and paste your Sheep token, or run setup.py for the "
        f"encrypted flow."
    )
    return 0


def check_for_updates() -> int:
    """Pull the latest release from GitHub via GitPython.

    Best-effort: requires the CLI to have been installed from a git
    clone with ``GitPython`` available. Refuses gracefully otherwise.
    """
    if not GIT_AVAILABLE:
        err_console.print(
            "[yellow]GitPython not installed. Install with: "
            "pip install GitPython[/yellow]\n"
            f"Or pull manually: cd {INSTALL_DIR} && git pull"
        )
        return 1
    try:
        if not (INSTALL_DIR / ".git").exists():
            err_console.print(
                f"[yellow]{INSTALL_DIR} is not a git checkout. "
                f"Reinstall via:[/yellow]\n"
                f"  curl -fsSL https://byfranke.com/feeds-cli-install | bash"
            )
            return 1
        repo = git.Repo(str(INSTALL_DIR))
        console.print("[cyan]Pulling latest from origin...[/cyan]")
        repo.remotes.origin.pull()
        version_file = INSTALL_DIR / "VERSION"
        new_version = version_file.read_text().strip() if version_file.exists() else "?"
        if new_version != VERSION:
            console.print(
                f"[green]Updated to version {new_version} (was {VERSION})[/green]"
            )
            console.print("[yellow]Upgrading dependencies...[/yellow]")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r",
                 str(INSTALL_DIR / "requirements.txt"), "--user", "--upgrade"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                console.print("[green][OK][/green] Dependencies upgraded")
            else:
                console.print(
                    "[yellow]Could not upgrade dependencies automatically.[/yellow]"
                )
                console.print(
                    f"Run manually: pip install -r {INSTALL_DIR}/requirements.txt --upgrade"
                )
        else:
            console.print(f"[green][OK][/green] Already at latest version ({VERSION})")
        return 0
    except Exception as e:
        err_console.print(f"[yellow]Could not check for updates: {_safe(str(e))}[/yellow]")
        err_console.print(f"For updates, visit: {GITHUB_REPO}")
        return 1


class WatchStore:
    """On-disk store for Watch rules, hits and per-feed state cursors.

    Layout under ``~/.sheep-feeds-cli/watch/``:

    - ``rules.yml`` — list of rule dicts (mode 0600). Each rule has
      ``id``, ``name``, ``enabled``, ``feed``, ``match`` (severity/
      contains/regex/category), ``notify`` (list), ``created_at``.
    - ``hits.db`` — SQLite (mode 0600) with one row per matched item;
      UNIQUE(rule_id, feed_id, item_id) prevents duplicate fires.
    - ``state.json`` — last-seen timestamp per feed_id; the run loop
      asks the server for items strictly after that mark.

    All I/O is fail-soft for non-fatal errors (load returns empty,
    record_hit swallows write errors after logging). YAML/SQLite hard
    failures during ``add_rule`` or ``remove_rule`` DO raise so the
    caller can show the user a real error.
    """

    def __init__(self) -> None:
        self._conn: Optional[sqlite3.Connection] = None

    @staticmethod
    def _ensure_dir() -> bool:
        try:
            WATCH_DIR.mkdir(parents=True, exist_ok=True)
            os.chmod(str(WATCH_DIR), 0o700)
            return True
        except OSError as e:
            err_console.print(f"[red]Cannot create {WATCH_DIR}: {_safe(str(e))}[/red]")
            return False

    @staticmethod
    def new_rule_id() -> str:
        return secrets.token_hex(3)

    def load_rules(self) -> List[Dict[str, Any]]:
        if not WATCH_RULES_FILE.exists():
            return []
        if not YAML_AVAILABLE:
            err_console.print(
                "[yellow]PyYAML not installed; cannot load watch rules. "
                "Install with: pip install PyYAML[/yellow]"
            )
            return []
        try:
            with open(WATCH_RULES_FILE, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except (OSError, yaml.YAMLError) as e:
            err_console.print(
                f"[yellow]Could not parse {WATCH_RULES_FILE}: {_safe(str(e))}[/yellow]"
            )
            return []
        if not isinstance(data, list):
            return []
        clean: List[Dict[str, Any]] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            rid = entry.get("id")
            name = entry.get("name")
            feed = entry.get("feed")
            if not isinstance(rid, str) or not isinstance(name, str):
                continue
            if not isinstance(feed, str):
                continue
            match = entry.get("match") or {}
            notify = entry.get("notify") or []
            if not isinstance(match, dict) or not isinstance(notify, list):
                continue
            clean.append({
                "id": rid,
                "name": name,
                "enabled": bool(entry.get("enabled", True)),
                "feed": feed,
                "match": {
                    "severity": match.get("severity"),
                    "category": match.get("category"),
                    "contains": match.get("contains"),
                    "regex": match.get("regex"),
                },
                "notify": [n for n in notify if isinstance(n, (str, dict))],
                "created_at": entry.get("created_at"),
            })
        return clean

    def save_rules(self, rules: List[Dict[str, Any]]) -> None:
        if not self._ensure_dir():
            raise RuntimeError(f"watch dir unavailable: {WATCH_DIR}")
        if not YAML_AVAILABLE:
            raise RuntimeError(
                "PyYAML not installed. Install with: pip install PyYAML"
            )
        tmp = WATCH_RULES_FILE.with_suffix(".yml.tmp")
        try:
            fd = os.open(
                str(tmp),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                yaml.safe_dump(rules, f, sort_keys=False, allow_unicode=True)
            os.replace(str(tmp), str(WATCH_RULES_FILE))
        except OSError as e:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise RuntimeError(f"cannot write rules: {e}")

    def add_rule(self, rule: Dict[str, Any]) -> None:
        rules = self.load_rules()
        if len(rules) >= WATCH_MAX_RULES:
            raise ValueError(
                f"Rule cap reached ({WATCH_MAX_RULES}). Remove unused rules "
                f"first: sheep-feeds watch remove <id|name>."
            )
        if any(r.get("name") == rule.get("name") for r in rules):
            raise ValueError(f"Rule name already exists: {rule.get('name')!r}")
        rules.append(rule)
        self.save_rules(rules)

    def remove_rule(self, ident: str) -> bool:
        rules = self.load_rules()
        before = len(rules)
        rules = [r for r in rules if r.get("id") != ident and r.get("name") != ident]
        if len(rules) == before:
            return False
        self.save_rules(rules)
        return True

    def set_enabled(self, ident: str, enabled: bool) -> bool:
        rules = self.load_rules()
        changed = False
        for r in rules:
            if r.get("id") == ident or r.get("name") == ident:
                r["enabled"] = bool(enabled)
                changed = True
        if changed:
            self.save_rules(rules)
        return changed

    def _open_db(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        if not self._ensure_dir():
            raise RuntimeError(f"watch dir unavailable: {WATCH_DIR}")
        conn = sqlite3.connect(str(WATCH_HITS_DB), timeout=10)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hits (
                rule_id    TEXT NOT NULL,
                rule_name  TEXT NOT NULL,
                feed_id    TEXT NOT NULL,
                item_id    TEXT NOT NULL,
                title      TEXT,
                url        TEXT,
                severity   TEXT,
                ts_hit     TEXT NOT NULL,
                payload    TEXT,
                PRIMARY KEY (rule_id, feed_id, item_id)
            )
            """
        )
        conn.commit()
        try:
            os.chmod(str(WATCH_HITS_DB), 0o600)
        except OSError:
            pass
        self._conn = conn
        return conn

    def record_hit(
        self,
        rule: Dict[str, Any],
        feed_id: str,
        item: Dict[str, Any],
    ) -> bool:
        try:
            conn = self._open_db()
            cur = conn.execute(
                "INSERT OR IGNORE INTO hits "
                "(rule_id, rule_name, feed_id, item_id, title, url, severity, ts_hit, payload) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    rule.get("id") or "",
                    rule.get("name") or "",
                    feed_id,
                    str(item.get("id") or ""),
                    str(item.get("title") or "")[:_MAX_FIELD_LEN],
                    str(item.get("url") or "")[:_MAX_FIELD_LEN],
                    str(item.get("severity") or "")[:64],
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps(item, ensure_ascii=False)[:8000],
                ),
            )
            conn.commit()
            return cur.rowcount == 1
        except sqlite3.Error as e:
            err_console.print(f"[yellow]record_hit failed: {_safe(str(e))}[/yellow]")
            return False

    def list_hits(
        self,
        since_iso: Optional[str] = None,
        rule_ident: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        try:
            conn = self._open_db()
        except RuntimeError:
            return []
        clauses: List[str] = []
        params: List[Any] = []
        if since_iso:
            clauses.append("ts_hit >= ?")
            params.append(since_iso)
        if rule_ident:
            clauses.append("(rule_id = ? OR rule_name = ?)")
            params.append(rule_ident)
            params.append(rule_ident)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        limit = max(1, min(1000, int(limit)))
        try:
            rows = conn.execute(
                "SELECT rule_id, rule_name, feed_id, item_id, title, url, "
                "severity, ts_hit, payload FROM hits"
                + where
                + " ORDER BY ts_hit DESC LIMIT ?",
                (*params, limit),
            ).fetchall()
        except sqlite3.Error:
            return []
        out: List[Dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row[8]) if row[8] else {}
            except (json.JSONDecodeError, ValueError):
                payload = {}
            out.append({
                "rule_id": row[0],
                "rule_name": row[1],
                "feed_id": row[2],
                "item_id": row[3],
                "title": row[4],
                "url": row[5],
                "severity": row[6],
                "ts_hit": row[7],
                "payload": payload,
            })
        return out

    def load_state(self) -> Dict[str, Any]:
        if not WATCH_STATE_FILE.exists():
            return {}
        try:
            with open(WATCH_STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def save_state(self, state: Dict[str, Any]) -> None:
        if not self._ensure_dir():
            return
        tmp = WATCH_STATE_FILE.with_suffix(".json.tmp")
        try:
            fd = os.open(
                str(tmp),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False, indent=2)
            os.replace(str(tmp), str(WATCH_STATE_FILE))
        except OSError:
            pass

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None


def _evaluate_rule(rule: Dict[str, Any], item: Dict[str, Any]) -> bool:
    """Return True when ``item`` matches the rule's ``match`` block.

    All match keys are AND-ed: every non-null key must hit. Substring
    comparisons are case-insensitive. Regex is compiled per call (cheap
    in CPython's re cache); the input is capped at
    ``WATCH_MAX_SEARCH_BYTES`` to bound any worst-case backtracking.
    """
    match = rule.get("match") or {}
    item_severity = str(item.get("severity") or "").lower()
    item_category = str(item.get("category") or "").lower()
    title = str(item.get("title") or "")
    content = str(item.get("content") or item.get("description") or "")
    haystack = f"{title}\n{content}"[:WATCH_MAX_SEARCH_BYTES].lower()

    severity = match.get("severity")
    if isinstance(severity, str) and severity:
        if severity.lower() not in item_severity:
            return False

    category = match.get("category")
    if isinstance(category, str) and category:
        if category.lower() not in item_category:
            return False

    contains = match.get("contains")
    if isinstance(contains, str) and contains:
        if contains.lower() not in haystack:
            return False

    regex = match.get("regex")
    if isinstance(regex, str) and regex:
        try:
            pat = re.compile(regex, re.IGNORECASE)
        except re.error:
            return False
        if not pat.search(haystack):
            return False

    return True


def _notify_desktop(title: str, body: str) -> bool:
    """Best-effort cross-platform desktop notification.

    Returns True on success. Falls back to a stderr print so the user
    still sees the alert when running watch in a foreground terminal.
    Probes the platform's native notifier:

    - Linux: ``notify-send`` (libnotify, present in every common DE)
    - macOS: ``osascript`` (built-in)
    - Windows: PowerShell's ``BurntToast`` if present; otherwise stderr
    """
    safe_title = _safe(title, max_len=120)
    safe_body = _safe(body, max_len=600)
    plain_title = _CONTROL_CHAR_RE.sub("", str(title))[:120]
    plain_body = _CONTROL_CHAR_RE.sub("", str(body))[:600]

    try:
        if sys.platform.startswith("linux"):
            ns = shutil.which("notify-send")
            if ns:
                subprocess.run(
                    [ns, "--app-name=Sheep Feeds", "--urgency=normal",
                     plain_title, plain_body],
                    timeout=WATCH_NOTIFY_TIMEOUT,
                    check=False,
                )
                return True
        elif sys.platform == "darwin":
            osa = shutil.which("osascript")
            if osa:
                escaped_title = plain_title.replace('"', "'")
                escaped_body = plain_body.replace('"', "'")
                subprocess.run(
                    [osa, "-e",
                     f'display notification "{escaped_body}" with title "{escaped_title}"'],
                    timeout=WATCH_NOTIFY_TIMEOUT,
                    check=False,
                )
                return True
        elif sys.platform.startswith("win"):
            ps = shutil.which("powershell.exe") or shutil.which("powershell")
            if ps:
                escaped_title = plain_title.replace("'", "''")
                escaped_body = plain_body.replace("'", "''")
                script = (
                    f"if (Get-Module -ListAvailable -Name BurntToast) "
                    f"{{ Import-Module BurntToast; "
                    f"New-BurntToastNotification -Text '{escaped_title}', '{escaped_body}' }} "
                    f"else {{ Write-Host '[Sheep] {escaped_title} - {escaped_body}' }}"
                )
                subprocess.run(
                    [ps, "-NoProfile", "-NonInteractive", "-Command", script],
                    timeout=WATCH_NOTIFY_TIMEOUT,
                    check=False,
                )
                return True
    except (subprocess.SubprocessError, OSError):
        pass

    err_console.print(f"[bold cyan]⚡ SHEEP WATCH[/bold cyan] {safe_title}")
    err_console.print(f"           {safe_body}")
    return False


def _notify_webhook(url: str, payload: Dict[str, Any]) -> bool:
    """POST a JSON payload to ``url``. Returns True on 2xx.

    No retry — the watch loop will rediscover the missed item next
    cycle if dedup hasn't been recorded. Validates the URL with
    ``_safe_url`` so a malformed entry in rules.yml does not become a
    request to an attacker-chosen host.
    """
    safe = _safe_url(url)
    if not safe:
        err_console.print(
            f"[yellow]Invalid webhook URL skipped: {_safe(url, max_len=120)}[/yellow]"
        )
        return False
    try:
        resp = requests.post(
            safe,
            json=payload,
            timeout=WATCH_NOTIFY_TIMEOUT,
            headers={"User-Agent": f"sheep-feeds-cli/{VERSION}"},
        )
        return 200 <= resp.status_code < 300
    except requests.exceptions.RequestException as e:
        err_console.print(f"[yellow]Webhook failed: {_safe(str(e))}[/yellow]")
        return False


def _dispatch_notifications(
    rule: Dict[str, Any],
    feed_id: str,
    item: Dict[str, Any],
) -> None:
    """Fire every channel listed in ``rule['notify']`` for one hit."""
    title = f"Sheep · {rule.get('name', '?')} · {feed_id}"
    item_title = str(item.get("title") or item.get("id") or "")[:200]
    item_severity = str(item.get("severity") or "?")
    body = f"[{item_severity}] {item_title}"
    payload = {
        "rule": {"id": rule.get("id"), "name": rule.get("name")},
        "feed_id": feed_id,
        "item": item,
        "fired_at": datetime.now(timezone.utc).isoformat(),
    }
    for channel in rule.get("notify") or []:
        if channel == "desktop":
            _notify_desktop(title, body)
        elif isinstance(channel, dict) and "webhook" in channel:
            _notify_webhook(str(channel["webhook"]), payload)
        elif isinstance(channel, str) and channel.startswith("http"):
            _notify_webhook(channel, payload)


def _feeds_for_rules(rules: List[Dict[str, Any]]) -> List[str]:
    """Return the set of feed_ids referenced by enabled rules.

    A rule with feed=='*' expands to the full ``KNOWN_FEEDS`` allowlist
    so the user can write one wildcard rule instead of nine.
    """
    feeds: set = set()
    for r in rules:
        if not r.get("enabled", True):
            continue
        f = r.get("feed")
        if f == "*":
            feeds.update(KNOWN_FEEDS)
        elif isinstance(f, str) and f:
            feeds.add(f)
    return sorted(feeds)


def run_watch_cycle(client: "SheepFeedsClient", store: WatchStore) -> Tuple[int, int]:
    """Run one scan over every feed referenced by enabled rules.

    Returns ``(items_scanned, hits_fired)``. Uses the per-feed state
    cursor to ask the server only for items newer than what we have
    already seen. The first run uses ``--last 24h`` to seed the cursor
    without flooding the user with everything in the rolling window.
    """
    rules = store.load_rules()
    enabled = [r for r in rules if r.get("enabled", True)]
    if not enabled:
        return 0, 0
    feeds = _feeds_for_rules(enabled)
    if not feeds:
        return 0, 0
    state = store.load_state()
    items_scanned = 0
    hits_fired = 0
    now_iso = datetime.now(timezone.utc).isoformat()

    for feed_id in feeds:
        cursor = state.get(feed_id)
        try:
            if cursor:
                data = client.get_feed(
                    feed_id,
                    limit=WATCH_FETCH_LIMIT,
                    offset=0,
                    since=cursor,
                )
            else:
                data = client.get_latest(feed_id, count=WATCH_FETCH_LIMIT)
        except (RuntimeError, ValueError) as e:
            err_console.print(
                f"[yellow]watch: feed {feed_id} fetch failed: {_safe(str(e))}[/yellow]"
            )
            continue
        items = data.get("items") or []
        items_scanned += len(items)
        feed_max_ts = cursor
        for item in items:
            if not isinstance(item, dict):
                continue
            ts = item.get("published_at") or item.get("timestamp")
            if isinstance(ts, str) and ts:
                if feed_max_ts is None or ts > feed_max_ts:
                    feed_max_ts = ts
            for rule in enabled:
                rfeed = rule.get("feed")
                if rfeed not in (feed_id, "*"):
                    continue
                if not _evaluate_rule(rule, item):
                    continue
                if store.record_hit(rule, feed_id, item):
                    _dispatch_notifications(rule, feed_id, item)
                    hits_fired += 1
        if feed_max_ts:
            state[feed_id] = feed_max_ts
    state["_last_run"] = now_iso
    store.save_state(state)
    return items_scanned, hits_fired


_WATCH_STOP = False


def _watch_signal_handler(signum, frame):
    global _WATCH_STOP
    _WATCH_STOP = True


def run_watch_loop(
    client: "SheepFeedsClient",
    store: WatchStore,
    interval: int,
    once: bool = False,
) -> int:
    """Main watch loop. Returns process exit code (0 on graceful stop)."""
    interval = max(WATCH_MIN_INTERVAL, min(WATCH_MAX_INTERVAL, int(interval)))
    if not once:
        signal.signal(signal.SIGINT, _watch_signal_handler)
        signal.signal(signal.SIGTERM, _watch_signal_handler)
        console.print(
            f"[cyan]sheep-feeds watch: starting loop "
            f"(interval={interval}s, ctrl-c to stop)[/cyan]"
        )

    while True:
        try:
            scanned, fired = run_watch_cycle(client, store)
            console.print(
                f"[dim]{datetime.now().strftime('%H:%M:%S')}[/dim] "
                f"watch cycle: scanned={scanned} fired={fired}"
            )
        except KeyboardInterrupt:
            break
        except Exception as e:
            err_console.print(f"[yellow]watch cycle error: {_safe(str(e))}[/yellow]")
        if once or _WATCH_STOP:
            break
        for _ in range(interval):
            if _WATCH_STOP:
                break
            time.sleep(1)
        if _WATCH_STOP:
            break

    store.close()
    if not once:
        console.print("[cyan]sheep-feeds watch: stopped[/cyan]")
    return 0


def _render_watch_rules(rules: List[Dict[str, Any]]) -> None:
    if not rules:
        console.print(
            "[yellow]No watch rules yet. "
            "Add one: sheep-feeds watch add <name> --feed cve --severity high "
            "--notify desktop[/yellow]"
        )
        return
    table = Table(show_lines=False)
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Feed")
    table.add_column("Match")
    table.add_column("Notify")
    table.add_column("On?")
    for r in rules:
        m = r.get("match") or {}
        match_bits = []
        for k in ("severity", "category", "contains", "regex"):
            v = m.get(k)
            if v:
                match_bits.append(f"{k}={_safe(str(v), 32)}")
        notify_bits = []
        for n in r.get("notify") or []:
            if isinstance(n, dict) and "webhook" in n:
                notify_bits.append("webhook")
            else:
                notify_bits.append(_safe(str(n), 16))
        enabled = bool(r.get("enabled", True))
        table.add_row(
            _safe(r.get("id"), 12),
            _safe(r.get("name"), 32),
            _safe(r.get("feed"), 24),
            _safe(", ".join(match_bits) or "(none)", 60),
            _safe(", ".join(notify_bits) or "(none)", 40),
            "[white]yes[/white]" if enabled else "[dim]paused[/dim]",
        )
    console.print(table)


def _render_watch_hits(hits: List[Dict[str, Any]]) -> None:
    if not hits:
        console.print("[yellow]No hits in the requested window.[/yellow]")
        return
    table = Table(show_lines=False)
    table.add_column("Fired", style="dim")
    table.add_column("Rule", style="bold")
    table.add_column("Feed")
    table.add_column("Severity")
    table.add_column("Title")
    for h in hits:
        table.add_row(
            _safe(h.get("ts_hit"), 20),
            _safe(h.get("rule_name"), 24),
            _safe(h.get("feed_id"), 18),
            _safe(h.get("severity"), 12),
            _safe(h.get("title"), 80),
        )
    console.print(table)


def _parse_window_since(value: Optional[str]) -> Optional[str]:
    """Convert ``--last 24h`` style window into an ISO timestamp.

    Reuses the existing ``_parse_last`` helper for parity with the
    ``get`` subcommand.
    """
    if not value:
        return None
    try:
        dt = _parse_last(value)
    except ValueError:
        return None
    return dt.replace(microsecond=0).isoformat()


def _build_pre_parser() -> argparse.ArgumentParser:
    """Minimal parser that extracts global flags BEFORE the subcommand
    is resolved. Used for two-pass parsing so flags work either side of
    the subcommand (see ``main``)."""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--token", default=None)
    p.add_argument("--api-url", default=None)
    p.add_argument("--json", action="store_true", default=False)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    return p


def _build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--token",
        help="Override the stored token (one-shot run).",
    )
    common.add_argument(
        "--api-url",
        help="Override the API base URL (default: %s)." % DEFAULT_API_BASE,
    )
    common.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of human-friendly tables.",
    )
    common.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="HTTP request timeout in seconds (default: %d)." % DEFAULT_TIMEOUT,
    )

    parser = argparse.ArgumentParser(
        prog="sheep-feeds-cli",
        description=(
            "Sheep threat-intelligence feeds CLI. Fetches CVEs, "
            "ransomware victims, IOCs and other curated feeds in JSON "
            "for use in SIEMs, SOAR playbooks and scripts."
        ),
        epilog=(
            f"Documentation: {GITHUB_REPO}\n"
            f"Support: {SUPPORT_EMAIL}"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common],
    )
    parser.add_argument("-V", "--version", action="version", version=VERSION)
    parser.add_argument("--about", action="store_true",
                        help="Show product info (license, links, features) and exit.")
    parser.add_argument("--init", action="store_true",
                        help="Create an empty ~/.sheep-feeds-cli/config.ini and exit.")
    parser.add_argument("--setup", action="store_true",
                        help="Launch the interactive setup wizard (setup.py) and exit.")
    parser.add_argument("--update", action="store_true",
                        help="Pull the latest release from GitHub and exit.")
    parser.add_argument("--logout", action="store_true",
                        help="Clear the cached decrypted token for the current terminal "
                             "session and exit.")

    sub = parser.add_subparsers(dest="command", required=False)

    sub.add_parser("list", parents=[common],
                   help="List all available feeds with metadata.")
    sub.add_parser("categories", parents=[common],
                   help="Group feeds by category.")
    sub.add_parser("summary", parents=[common],
                   help="Compact dashboard-style summary across all feeds.")
    sub.add_parser("plan", parents=[common],
                   help="Show your plan, status and current-period token usage.")

    p_get = sub.add_parser("get", parents=[common],
                           help="Fetch items from a feed.")
    p_get.add_argument("feed_id", help="Feed identifier (e.g. cve, ransomware).")
    p_get.add_argument("--limit", type=int, default=50, help="Max items (1-500).")
    p_get.add_argument("--offset", type=int, default=0, help="Pagination offset.")
    p_get.add_argument(
        "--since", help="ISO-8601 timestamp; only return items after this."
    )
    p_get.add_argument(
        "--last",
        help=(
            "Time-window shortcut: 24h, 3d, 2w, or aliases "
            "today/yesterday/week/month. Mutually exclusive with --since."
        ),
    )
    p_get.add_argument(
        "--severity",
        help="Filter by severity substring (case-insensitive).",
    )
    p_get.add_argument("--category", help="Filter by category substring.")

    p_latest = sub.add_parser(
        "latest", parents=[common],
        help="Shortcut for the N newest items from a feed."
    )
    p_latest.add_argument("feed_id", help="Feed identifier.")
    p_latest.add_argument("--count", type=int, default=10, help="Items to return (1-100).")
    p_latest.add_argument(
        "--last",
        help=(
            "Restrict the search window before picking the N newest "
            "(forms: 24h, 3d, 2w, today/yesterday/week/month). "
            "Calls /get under the hood when present."
        ),
    )

    p_stats = sub.add_parser("stats", parents=[common],
                             help="Per-feed statistics.")
    p_stats.add_argument("feed_id", help="Feed identifier.")

    p_watch = sub.add_parser(
        "watch", parents=[common],
        help="Local rules engine that watches the feeds and notifies you on hit.",
    )
    p_watch_sub = p_watch.add_subparsers(dest="watch_command", required=False)

    p_w_add = p_watch_sub.add_parser(
        "add", help="Create a new rule. Example: "
                    "sheep-feeds watch add nginx-high --feed cve --contains nginx "
                    "--severity high --notify desktop"
    )
    p_w_add.add_argument("name", help="Rule name (lowercase, a-z0-9_-, max 32).")
    p_w_add.add_argument("--feed", required=True,
                         help="Feed id (e.g. cve, ransomware) or '*' for every feed.")
    p_w_add.add_argument("--severity", choices=WATCH_SEVERITY_CHOICES, default=None)
    p_w_add.add_argument("--category", default=None,
                         help="Substring match on the item's category.")
    p_w_add.add_argument("--contains", default=None,
                         help="Case-insensitive substring search in title + content.")
    p_w_add.add_argument("--regex", default=None,
                         help="Regex search in title + content (Python flavor).")
    p_w_add.add_argument(
        "--notify", action="append", default=None,
        help="Channel: 'desktop' or a https:// webhook URL. "
             "Repeat to add multiple. Default: desktop.",
    )

    p_w_list = p_watch_sub.add_parser("list", help="List every rule, enabled or paused.")
    p_w_list.add_argument("--json", action="store_true", default=False,
                           help="Print raw JSON instead of a table.")

    p_w_remove = p_watch_sub.add_parser("remove", help="Delete a rule by id or name.")
    p_w_remove.add_argument("ident", help="Rule id or name.")

    p_w_pause = p_watch_sub.add_parser("pause", help="Disable a rule without removing it.")
    p_w_pause.add_argument("ident", help="Rule id or name.")

    p_w_resume = p_watch_sub.add_parser("resume", help="Re-enable a paused rule.")
    p_w_resume.add_argument("ident", help="Rule id or name.")

    p_w_hits = p_watch_sub.add_parser(
        "hits",
        help="Show recent hits (use --last 24h, --rule <id|name>, --json).",
    )
    p_w_hits.add_argument("--last", default="24h",
                          help="Time-window: 24h, 3d, 2w, today, yesterday, week, month.")
    p_w_hits.add_argument("--rule", default=None,
                          help="Filter by rule id or name.")
    p_w_hits.add_argument("--limit", type=int, default=100,
                          help="Max hits returned (1-1000).")
    p_w_hits.add_argument("--json", action="store_true", default=False,
                          help="Print raw JSON instead of a table.")

    p_w_run = p_watch_sub.add_parser(
        "run",
        help="Start the watch loop. Use --once for cron mode, or omit for daemon mode.",
    )
    p_w_run.add_argument("--once", action="store_true",
                         help="Run a single scan and exit. Pair with cron / systemd timer.")
    p_w_run.add_argument(
        "--interval", type=int, default=WATCH_DEFAULT_INTERVAL,
        help=f"Seconds between scans in daemon mode "
             f"(min {WATCH_MIN_INTERVAL}, max {WATCH_MAX_INTERVAL}, "
             f"default {WATCH_DEFAULT_INTERVAL}).",
    )

    return parser




def _print_json(data: Dict[str, Any]) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True))


def _dispatch_watch(args: argparse.Namespace, client: "SheepFeedsClient") -> int:
    """Route a ``sheep-feeds watch <verb>`` invocation to the right handler.

    Handlers validate input, mutate the on-disk store, render Rich
    tables for humans, or emit JSON for pipes. Always returns a
    POSIX-style exit code (0 success, 1 runtime error, 2 user input).
    """
    sub = getattr(args, "watch_command", None)
    if not sub:
        console.print(
            "[yellow]Watch subcommands: add, list, remove, pause, resume, "
            "hits, run. See 'sheep-feeds watch --help'.[/yellow]"
        )
        return 0

    store = WatchStore()

    if sub == "list":
        rules = store.load_rules()
        if args.json:
            _print_json({"rules": rules, "total": len(rules)})
        else:
            _render_watch_rules(rules)
        return 0

    if sub == "add":
        name = (args.name or "").strip()
        if not WATCH_NAME_RE.match(name):
            err_console.print(
                "[red]Invalid name. Use lowercase letters, digits, _ or -, "
                "max 32 chars, starting with a letter or digit.[/red]"
            )
            return 2
        feed = (args.feed or "").strip()
        if feed != "*" and feed not in KNOWN_FEEDS:
            err_console.print(
                f"[red]Unknown feed: {_safe(feed)}. "
                f"Allowed: {', '.join(KNOWN_FEEDS)} or '*'.[/red]"
            )
            return 2
        if args.regex:
            try:
                re.compile(args.regex)
            except re.error as e:
                err_console.print(f"[red]Invalid regex: {_safe(str(e))}[/red]")
                return 2
        notify_raw = args.notify or ["desktop"]
        notify: List[Any] = []
        for n in notify_raw:
            ns = n.strip()
            if ns == "desktop":
                notify.append("desktop")
            elif ns.startswith(("http://", "https://")):
                if not _safe_url(ns):
                    err_console.print(
                        f"[red]Invalid webhook URL: {_safe(ns)}[/red]"
                    )
                    return 2
                notify.append({"webhook": ns})
            else:
                err_console.print(
                    f"[red]Unknown notify channel: {_safe(ns)}. "
                    f"Use 'desktop' or an http(s) URL.[/red]"
                )
                return 2
        match = {
            "severity": args.severity,
            "category": args.category,
            "contains": args.contains,
            "regex": args.regex,
        }
        if not any(v for v in match.values()):
            err_console.print(
                "[red]At least one of --severity / --category / --contains / "
                "--regex must be set, otherwise the rule fires on every item.[/red]"
            )
            return 2
        rule = {
            "id": WatchStore.new_rule_id(),
            "name": name,
            "enabled": True,
            "feed": feed,
            "match": match,
            "notify": notify,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            store.add_rule(rule)
        except (ValueError, RuntimeError) as e:
            err_console.print(f"[red]{_safe(str(e))}[/red]")
            return 2
        console.print(
            f"[green]Rule [bold]{name}[/bold] added "
            f"(id [dim]{rule['id']}[/dim]).[/green]"
        )
        return 0

    if sub == "remove":
        ident = (args.ident or "").strip()
        if not ident:
            err_console.print("[red]Provide a rule id or name.[/red]")
            return 2
        if not store.remove_rule(ident):
            err_console.print(f"[yellow]No rule matched: {_safe(ident)}[/yellow]")
            return 1
        console.print(f"[green]Rule {_safe(ident)} removed.[/green]")
        return 0

    if sub in ("pause", "resume"):
        ident = (args.ident or "").strip()
        if not ident:
            err_console.print("[red]Provide a rule id or name.[/red]")
            return 2
        ok = store.set_enabled(ident, enabled=(sub == "resume"))
        if not ok:
            err_console.print(f"[yellow]No rule matched: {_safe(ident)}[/yellow]")
            return 1
        verb = "paused" if sub == "pause" else "resumed"
        console.print(f"[green]Rule {_safe(ident)} {verb}.[/green]")
        return 0

    if sub == "hits":
        since_iso = _parse_window_since(getattr(args, "last", None))
        limit = max(1, min(1000, int(getattr(args, "limit", 100) or 100)))
        rule_filter = getattr(args, "rule", None)
        hits = store.list_hits(
            since_iso=since_iso, rule_ident=rule_filter, limit=limit
        )
        if args.json:
            _print_json({"hits": hits, "count": len(hits)})
        else:
            _render_watch_hits(hits)
        return 0

    if sub == "run":
        once = bool(getattr(args, "once", False))
        interval = int(getattr(args, "interval", WATCH_DEFAULT_INTERVAL))
        rules = store.load_rules()
        enabled = [r for r in rules if r.get("enabled", True)]
        if not enabled:
            err_console.print(
                "[yellow]No enabled rules. Add one first: "
                "sheep-feeds watch add <name> --feed <id> ...[/yellow]"
            )
            return 1
        return run_watch_loop(client, store, interval=interval, once=once)

    err_console.print(f"[red]Unknown watch verb: {_safe(str(sub))}[/red]")
    return 2


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    pre_args, _ = _build_pre_parser().parse_known_args(argv)
    args = parser.parse_args(argv)

    args.token = args.token or pre_args.token
    args.api_url = args.api_url or pre_args.api_url
    args.json = bool(args.json or pre_args.json)
    args.timeout = args.timeout if args.timeout != DEFAULT_TIMEOUT else pre_args.timeout

    if args.about:
        about_info = (
            f"[bold cyan]Sheep Feeds CLI v{VERSION}[/bold cyan]\n"
            f"Threat-intelligence feeds for CTI workflows.\n\n"
            f"[bold]Copyright:[/bold] (c) 2026 byFranke - Security Solutions\n"
            f"[bold]License:[/bold] byFranke License\n"
            f"[bold]GitHub:[/bold] {GITHUB_REPO}\n"
            f"[bold]Privacy Policy:[/bold] {PRIVACY_POLICY}\n"
            f"[bold]Support:[/bold] {SUPPORT_EMAIL}\n\n"
            f"[bold]Features:[/bold]\n"
            f"- Fetch CVEs, ransomware victims, IOCs, ICS/SCADA advisories and more\n"
            f"- Filters: --since, --last, --severity, --category\n"
            f"- Pagination: --limit, --offset\n"
            f"- Output: pretty tables (default) or raw --json\n"
            f"- Encrypted token storage with per-session cache\n"
            f"- Subcommand 'plan' to view your plan, quota and active token\n"
            f"- Subcommand 'watch' to define rules and get desktop / webhook\n"
            f"  alerts when feeds match (no token cost)\n"
        )
        console.print(Panel(about_info, title="About Sheep Feeds CLI", style="cyan"))
        return 0

    if args.logout:
        try:
            client = SheepFeedsClient.__new__(SheepFeedsClient)
            cache = client._session_cache_path()
            if cache and cache.exists():
                cache.unlink()
                console.print("[green]Session token cache cleared[/green]")
            else:
                console.print("[yellow]No cached session token to clear[/yellow]")
        except Exception as e:
            err_console.print(
                f"[red]Failed to clear session cache: {_safe(str(e), max_len=200)}[/red]"
            )
        return 0

    if args.setup:
        console.print("[cyan]Launching setup wizard...[/cyan]")
        script_dir = Path(__file__).resolve().parent
        rc = subprocess.call([sys.executable, str(script_dir / "setup.py")])
        return rc

    if args.update:
        return check_for_updates()

    if args.init:
        return init_config()

    if not args.command:
        parser.print_help()
        return 0

    try:
        client = SheepFeedsClient(api_token=args.token, api_url=args.api_url)
    except ValueError as e:
        err_console.print(f"[red]{e}[/red]")
        return 2

    try:
        if args.command == "list":
            data = client.list_feeds()
            if args.json:
                _print_json(data)
            else:
                _render_feed_list(data)

        elif args.command == "categories":
            data = client.list_categories()
            if args.json:
                _print_json(data)
            else:
                _render_categories(data)

        elif args.command == "summary":
            data = client.get_summary()
            if args.json:
                _print_json(data)
            else:
                _render_summary(data)

        elif args.command == "get":
            if args.limit < 1 or args.limit > 500:
                err_console.print("[red]--limit must be between 1 and 500.[/red]")
                return 2
            if args.offset < 0:
                err_console.print("[red]--offset must be >= 0.[/red]")
                return 2

            since = args.since
            if args.last:
                if since:
                    err_console.print(
                        "[red]--since and --last are mutually exclusive. "
                        "Pick one.[/red]"
                    )
                    return 2
                try:
                    since_dt = _parse_last(args.last)
                except ValueError as ve:
                    err_console.print(f"[red]{ve}[/red]")
                    return 2
                since = since_dt.replace(microsecond=0).isoformat()

            data = client.get_feed(
                args.feed_id,
                limit=args.limit,
                offset=args.offset,
                since=since,
                severity=args.severity,
                category=args.category,
            )
            if args.json:
                _print_json(data)
            else:
                _render_feed_items(data)

        elif args.command == "latest":
            if args.count < 1 or args.count > 100:
                err_console.print("[red]--count must be between 1 and 100.[/red]")
                return 2

            if args.last:
                try:
                    since_dt = _parse_last(args.last)
                except ValueError as ve:
                    err_console.print(f"[red]{ve}[/red]")
                    return 2
                since_iso = since_dt.replace(microsecond=0).isoformat()
                data = client.get_feed(
                    args.feed_id,
                    limit=args.count,
                    offset=0,
                    since=since_iso,
                )
            else:
                data = client.get_latest(args.feed_id, count=args.count)

            if args.json:
                _print_json(data)
            else:
                data.setdefault("feed_name", args.feed_id)
                _render_feed_items(data)

        elif args.command == "stats":
            data = client.get_stats(args.feed_id)
            if args.json:
                _print_json(data)
            else:
                _render_stats(data)

        elif args.command == "plan":
            data = client.get_profile(timeout=args.timeout)
            if args.json:
                _print_json(data)
            else:
                display_profile(data)

        elif args.command == "watch":
            return _dispatch_watch(args, client)

        else:
            parser.print_help()
            return 0

    except ValueError as e:
        err_console.print(f"[red]{e}[/red]")
        return 2
    except RuntimeError as e:
        err_console.print(f"[red]{e}[/red]")
        return 1
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Cancelled.[/yellow]")
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
