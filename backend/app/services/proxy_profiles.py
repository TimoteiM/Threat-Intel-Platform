"""Per-investigation outbound proxy profile helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, unquote, urlparse, urlunparse

from app.config import get_settings


# Active residential-proxy geographies returned by ANY.RUN's
# getResidentialProxyGeos configuration method. Keep this mapping explicit so
# the API can return useful labels and deployments can opt into the complete
# set with ANYRUN_PROXY_COUNTRIES=*.
ANYRUN_RESIDENTIAL_PROXY_COUNTRIES: dict[str, str] = {
    "AF": "Afghanistan",
    "AL": "Albania",
    "DZ": "Algeria",
    "AD": "Andorra",
    "AO": "Angola",
    "AG": "Antigua and Barbuda",
    "AR": "Argentina",
    "AM": "Armenia",
    "AU": "Australia",
    "AT": "Austria",
    "AZ": "Azerbaijan",
    "BS": "Bahamas",
    "BH": "Bahrain",
    "BD": "Bangladesh",
    "BB": "Barbados",
    "BY": "Belarus",
    "BE": "Belgium",
    "BZ": "Belize",
    "BJ": "Benin",
    "BT": "Bhutan",
    "BO": "Bolivia",
    "BA": "Bosnia and Herzegovina",
    "BW": "Botswana",
    "BR": "Brazil",
    "BN": "Brunei",
    "BG": "Bulgaria",
    "BF": "Burkina Faso",
    "CV": "Cabo Verde",
    "KH": "Cambodia",
    "CM": "Cameroon",
    "CA": "Canada",
    "KY": "Cayman Islands",
    "CL": "Chile",
    "CN": "China",
    "CO": "Colombia",
    "CG": "Congo",
    "CD": "Democratic Republic of the Congo",
    "CR": "Costa Rica",
    "CI": "Côte d’Ivoire",
    "HR": "Croatia",
    "CU": "Cuba",
    "CW": "Curaçao",
    "CY": "Cyprus",
    "CZ": "Czech Republic",
    "DK": "Denmark",
    "DM": "Dominica",
    "DO": "Dominican Republic",
    "EC": "Ecuador",
    "EG": "Egypt",
    "SV": "El Salvador",
    "EE": "Estonia",
    "ET": "Ethiopia",
    "FJ": "Fiji",
    "FI": "Finland",
    "FR": "France",
    "GF": "French Guiana",
    "PF": "French Polynesia",
    "GA": "Gabon",
    "GM": "Gambia",
    "GE": "Georgia",
    "DE": "Germany",
    "GH": "Ghana",
    "GR": "Greece",
    "GD": "Grenada",
    "GP": "Guadeloupe",
    "GU": "Guam",
    "GT": "Guatemala",
    "GN": "Guinea",
    "GY": "Guyana",
    "HT": "Haiti",
    "HN": "Honduras",
    "HK": "Hong Kong",
    "HU": "Hungary",
    "IS": "Iceland",
    "IN": "India",
    "ID": "Indonesia",
    "IR": "Iran",
    "IQ": "Iraq",
    "IE": "Ireland",
    "IM": "Isle of Man",
    "IL": "Israel",
    "IT": "Italy",
    "JM": "Jamaica",
    "JP": "Japan",
    "JE": "Jersey",
    "JO": "Jordan",
    "KZ": "Kazakhstan",
    "KE": "Kenya",
    "KR": "South Korea",
    "KW": "Kuwait",
    "KG": "Kyrgyzstan",
    "LA": "Laos",
    "LV": "Latvia",
    "LB": "Lebanon",
    "LS": "Lesotho",
    "LR": "Liberia",
    "LY": "Libya",
    "LT": "Lithuania",
    "LU": "Luxembourg",
    "MO": "Macao",
    "MK": "North Macedonia",
    "MG": "Madagascar",
    "MW": "Malawi",
    "MY": "Malaysia",
    "ML": "Mali",
    "MT": "Malta",
    "MQ": "Martinique",
    "MR": "Mauritania",
    "MU": "Mauritius",
    "YT": "Mayotte",
    "MX": "Mexico",
    "MD": "Moldova",
    "MN": "Mongolia",
    "ME": "Montenegro",
    "MA": "Morocco",
    "MZ": "Mozambique",
    "MM": "Myanmar",
    "NA": "Namibia",
    "NP": "Nepal",
    "NL": "Netherlands",
    "NZ": "New Zealand",
    "NI": "Nicaragua",
    "NE": "Niger",
    "NG": "Nigeria",
    "NO": "Norway",
    "OM": "Oman",
    "PK": "Pakistan",
    "PS": "Palestine",
    "PA": "Panama",
    "PG": "Papua New Guinea",
    "PY": "Paraguay",
    "PE": "Peru",
    "PH": "Philippines",
    "PL": "Poland",
    "PT": "Portugal",
    "PR": "Puerto Rico",
    "QA": "Qatar",
    "RE": "Réunion",
    "RO": "Romania",
    "RU": "Russia",
    "RW": "Rwanda",
    "LC": "Saint Lucia",
    "SA": "Saudi Arabia",
    "SN": "Senegal",
    "RS": "Serbia",
    "SC": "Seychelles",
    "SL": "Sierra Leone",
    "SG": "Singapore",
    "SX": "Sint Maarten",
    "SK": "Slovakia",
    "SI": "Slovenia",
    "SO": "Somalia",
    "ZA": "South Africa",
    "SS": "South Sudan",
    "ES": "Spain",
    "LK": "Sri Lanka",
    "SD": "Sudan",
    "SR": "Suriname",
    "SZ": "Eswatini",
    "SE": "Sweden",
    "CH": "Switzerland",
    "SY": "Syria",
    "TW": "Taiwan",
    "TJ": "Tajikistan",
    "TZ": "Tanzania",
    "TH": "Thailand",
    "TG": "Togo",
    "TT": "Trinidad and Tobago",
    "TN": "Tunisia",
    "TR": "Turkey",
    "UG": "Uganda",
    "UA": "Ukraine",
    "AE": "United Arab Emirates",
    "GB": "United Kingdom",
    "US": "United States",
    "UY": "Uruguay",
    "UZ": "Uzbekistan",
    "VE": "Venezuela",
    "VN": "Vietnam",
    "VI": "U.S. Virgin Islands",
    "YE": "Yemen",
    "ZM": "Zambia",
    "ZW": "Zimbabwe",
}


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
                "label": ANYRUN_RESIDENTIAL_PROXY_COUNTRIES.get(country, country),
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
            "label": ANYRUN_RESIDENTIAL_PROXY_COUNTRIES.get(country, country),
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
    if any(part.strip().upper() in {"*", "ALL"} for part in raw.split(",")):
        return set(ANYRUN_RESIDENTIAL_PROXY_COUNTRIES)
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
