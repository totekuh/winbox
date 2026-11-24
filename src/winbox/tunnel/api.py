"""REST API client for ligolo-ng proxy (daemon mode)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any

from winbox.tunnel import API_PASS, API_PORT, API_USER

if TYPE_CHECKING:
    from winbox.config import Config


class ApiError(RuntimeError):
    """Ligolo REST API call failed."""


def _base(cfg: Config) -> str:
    return f"http://127.0.0.1:{API_PORT}"


def _request(
    cfg: Config,
    method: str,
    path: str,
    body: dict | None = None,
    *,
    token: str | None = None,
) -> dict:
    url = f"{_base(cfg)}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read())
        except Exception:
            detail = {"status": e.code}
        raise ApiError(f"{method} {path} -> {e.code}: {detail}") from e
    except urllib.error.URLError as e:
        raise ApiError(f"{method} {path} -> {e.reason}") from e


def ping(cfg: Config) -> bool:
    """True if the API is responding."""
    try:
        _request(cfg, "POST", "/api/auth", {"Username": API_USER, "Password": API_PASS})
        return True
    except Exception:
        return False


def auth(cfg: Config) -> str:
    """Authenticate and return JWT token."""
    resp = _request(cfg, "POST", "/api/auth", {"Username": API_USER, "Password": API_PASS})
    token = resp.get("token")
    if not token:
        raise ApiError("auth returned no token")
    return token


def agents(cfg: Config, token: str) -> list[dict]:
    """List connected agents."""
    resp = _request(cfg, "GET", "/api/v1/agents", token=token)
    if isinstance(resp, dict):
        return [{"id": int(k), **v} for k, v in resp.items()]
    return resp or []


def create_interface(cfg: Config, token: str, name: str) -> str:
    resp = _request(cfg, "POST", "/api/v1/interfaces", {"Interface": name}, token=token)
    return resp.get("message", "")


def delete_interface(cfg: Config, token: str, name: str) -> str:
    resp = _request(cfg, "DELETE", "/api/v1/interfaces", {"Interface": name}, token=token)
    return resp.get("message", "")


def add_routes(cfg: Config, token: str, interface: str, routes: list[str]) -> str:
    resp = _request(
        cfg, "POST", "/api/v1/routes",
        {"Interface": interface, "Route": routes},
        token=token,
    )
    return resp.get("message", "")


def delete_route(cfg: Config, token: str, interface: str, route: str) -> str:
    resp = _request(
        cfg, "DELETE", "/api/v1/routes",
        {"Interface": interface, "Route": route},
        token=token,
    )
    return resp.get("message", "")


def start_tunnel(cfg: Config, token: str, agent_id: int, interface: str) -> str:
    resp = _request(
        cfg, "POST", f"/api/v1/tunnel/{agent_id}",
        {"Interface": interface},
        token=token,
    )
    return resp.get("message", "")


def stop_tunnel(cfg: Config, token: str, agent_id: int) -> str:
    resp = _request(cfg, "DELETE", f"/api/v1/tunnel/{agent_id}", token=token)
    return resp.get("message", "")


def list_interfaces(cfg: Config, token: str) -> dict[str, Any]:
    return _request(cfg, "GET", "/api/v1/interfaces", token=token)


def list_listeners(cfg: Config, token: str) -> list[dict]:
    resp = _request(cfg, "GET", "/api/v1/listeners", token=token)
    return resp or []
