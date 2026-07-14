"""Per-investigation outbound proxy profile helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, unquote, urlparse, urlunparse

from app.config import get_settings


@dataclass(frozen=True)
class ProxyProfile:
    country: str
    label: str
    proxy_url: str

    @property
    def safe_summary(self) -> dict[str, str]:
        return {
            "country": self.country,
            "label": self.label,
            "configured": "true",
        }

    @property
    def requests_proxies(self) -> dict[str, str]:
        return {"http": self.proxy_url, "https": self.proxy_url}

    @property
    def playwright_proxy(self) -> dict[str, str]:
        parsed = urlparse(self.proxy_url)
        server = urlunparse((parsed.scheme, parsed.hostname or "", "", "", "", ""))
        if parsed.port:
            server = urlunparse((parsed.scheme, f"{parsed.hostname}:{parsed.port}", "", "", "", ""))
        proxy: dict[str, str] = {"server": server}
        if parsed.username:
            proxy["username"] = unquote(parsed.username)
        if parsed.password:
            proxy["password"] = unquote(parsed.password)
        return proxy


def configured_proxy_profiles() -> list[dict[str, str]]:
    countries: dict[str, dict[str, str]] = {}
    for profile in _profiles().values():
        countries[profile.country] = {
            **profile.safe_summary,
            "local_proxy": "true",
            "anyrun_residential": "true",
        }
    for country in _anyrun_proxy_countries():
        countries.setdefault(
            country,
            {
                "country": country,
                "label": country,
                "configured": "true",
                "local_proxy": "false",
                "anyrun_residential": "true",
            },
        )
    return [countries[key] for key in sorted(countries)]


def is_configured_network_country(country: str | None) -> bool:
    code = _normalize_country(country)
    if not code:
        return False
    return code in _profiles() or code in _anyrun_proxy_countries()


def resolve_proxy_profile(country: str | None) -> ProxyProfile | None:
    code = _normalize_country(country)
    if not code:
        return None
    return _profiles().get(code)


def selected_proxy_profile(external_context: dict[str, Any] | None) -> ProxyProfile | None:
    if not isinstance(external_context, dict):
        return None
    network = external_context.get("network_profile") or {}
    if not isinstance(network, dict):
        return None
    return resolve_proxy_profile(network.get("proxy_country"))


def selected_proxy_summary(external_context: dict[str, Any] | None) -> dict[str, str] | None:
    if not isinstance(external_context, dict):
        return None
    network = external_context.get("network_profile") or {}
    if not isinstance(network, dict):
        return None
    country = _normalize_country(network.get("proxy_country"))
    if not country:
        return None
    profile = resolve_proxy_profile(country)
    if profile:
        return {
            **profile.safe_summary,
            "local_proxy": "true",
            "anyrun_residential": "true",
        }
    if country in _anyrun_proxy_countries():
        return {
            "country": country,
            "label": country,
            "configured": "true",
            "local_proxy": "false",
            "anyrun_residential": "true",
        }
    return {"country": country, "label": country, "configured": "false"}


def _profiles() -> dict[str, ProxyProfile]:
    profiles: dict[str, ProxyProfile] = {}
    raw = get_settings().proxy_profiles or ""
    for part in raw.split(","):
        item = part.strip()
        if not item or "=" not in item:
            continue
        country_raw, url_raw = item.split("=", 1)
        country = _normalize_country(country_raw)
        proxy_url = _normalize_proxy_url(url_raw.strip())
        if not country or not proxy_url:
            continue
        profiles[country] = ProxyProfile(country=country, label=country, proxy_url=proxy_url)
    return profiles


def _anyrun_proxy_countries() -> set[str]:
    raw = getattr(get_settings(), "anyrun_proxy_countries", "") or ""
    countries: set[str] = set()
    for part in raw.split(","):
        country = _normalize_country(part)
        if country:
            countries.add(country)
    return countries


def _normalize_country(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text in {"", "DIRECT", "NONE", "NO_PROXY"}:
        return ""
    return "".join(ch for ch in text if ch.isalnum())[:12]


def _normalize_proxy_url(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = f"http://{text}"
    parsed = urlparse(text)
    if not parsed.scheme or not parsed.hostname:
        return ""
    if parsed.username or parsed.password:
        username = quote(unquote(parsed.username or ""), safe="")
        password = quote(unquote(parsed.password or ""), safe="")
        host = parsed.hostname or ""
        if parsed.port:
            host = f"{host}:{parsed.port}"
        netloc = f"{username}:{password}@{host}" if password else f"{username}@{host}"
        return urlunparse((parsed.scheme, netloc, "", "", "", ""))
    return text
