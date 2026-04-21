"""
401/403 error classifier for openai-codex provider.

Pure string/shape matching — no I/O, no side effects.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, Optional

Category = Literal[
    "refreshable",
    "reauth",
    "non_auth",
    "config",
    "unknown",
]


@dataclass(frozen=True)
class AuthErrorVerdict:
    category: Category
    reason: str
    user_message: Optional[str] = None


_REAUTH_PATTERNS = [
    (re.compile(r"oauth token refresh failed", re.I), "oauth_refresh_failed"),
    (re.compile(r"\binvalid_grant\b", re.I), "invalid_grant"),
    (re.compile(r"invalid[_\s-]?refresh[_\s-]?token", re.I), "invalid_refresh_token"),
    (re.compile(r"refresh[_\s-]?token[_\s-]?reused", re.I), "refresh_token_reused"),
    (re.compile(r"\brevoked\b", re.I), "token_revoked"),
    (re.compile(r"sign in again|please re-?authenticate", re.I), "sign_in_again"),
    (re.compile(r"missing scope|insufficient[_\s]scopes?", re.I), "missing_scope"),
    (re.compile(r"codex[^\n]{0,40}scope", re.I), "codex_scope_missing"),
]

_CONFIG_PATTERNS = [
    (re.compile(r"could not parse your authentication token", re.I), "unparseable_token"),
    (re.compile(r'no api key found for provider "?openai"?', re.I), "no_api_key_for_openai"),
    (re.compile(r"provider mismatch", re.I), "provider_mismatch"),
    (re.compile(r"endpoint mismatch", re.I), "endpoint_mismatch"),
]

_NON_AUTH_PATTERNS = [
    (re.compile(r"usage[_\s]limit[_\s]reached", re.I), "usage_limit"),
    (re.compile(r"\bcooldown\b", re.I), "cooldown"),
    (re.compile(r"rate[_\s]?limit", re.I), "rate_limit"),
    (re.compile(r"\btimeout\b|timed out", re.I), "timeout"),
    (re.compile(r"fetch failed|network error|ECONNRESET|ENOTFOUND", re.I), "network"),
    (re.compile(r"pairing required", re.I), "pairing_required"),
]

_REFRESHABLE_PATTERNS = [
    (re.compile(r"token (?:has )?expired", re.I), "token_expired"),
    (re.compile(r"\bexpired\b", re.I), "generic_expired"),
    (re.compile(r"access[_\s]token[_\s]expired", re.I), "access_token_expired"),
]


def _looks_like_html_403(body: str) -> bool:
    if not body:
        return False
    head = body.lstrip()[:256].lower()
    if not head.startswith(("<!doctype", "<html")):
        return False
    lower = body.lower()
    return (
        "cloudflare" in lower
        or "attention required" in lower
        or "just a moment" in lower
        or "sign in" in lower
    )


def classify_401(
    *,
    status: int,
    body: str = "",
    error_code: Optional[str] = None,
    token_near_expiry: bool = False,
) -> AuthErrorVerdict:
    """Decide what to do with a 401/403 from openai-codex."""
    text = f"{error_code or ''}\n{body or ''}"

    if status == 403 and _looks_like_html_403(body):
        return AuthErrorVerdict(
            category="reauth",
            reason="html_403_auth_page",
            user_message="Provider returned a sign-in page. Please re-authenticate.",
        )

    if status != 401:
        return AuthErrorVerdict(category="unknown", reason=f"status_{status}")

    for pat, name in _REAUTH_PATTERNS:
        if pat.search(text):
            return AuthErrorVerdict(
                category="reauth",
                reason=name,
                user_message="Your Codex credentials can't be refreshed. Please sign in again.",
            )

    for pat, name in _CONFIG_PATTERNS:
        if pat.search(text):
            return AuthErrorVerdict(
                category="config",
                reason=name,
                user_message=(
                    "This looks like a provider/endpoint configuration issue, "
                    "not an expired token. Check that the openai-codex provider "
                    "is routed correctly."
                ),
            )

    for pat, name in _NON_AUTH_PATTERNS:
        if pat.search(text):
            return AuthErrorVerdict(category="non_auth", reason=name)

    for pat, name in _REFRESHABLE_PATTERNS:
        if pat.search(text):
            return AuthErrorVerdict(category="refreshable", reason=name)

    if token_near_expiry:
        return AuthErrorVerdict(category="refreshable", reason="local_ttl_near_expiry")

    return AuthErrorVerdict(category="unknown", reason="no_rule_matched")
