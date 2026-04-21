"""
Unit tests for _auth_error_classifier.classify_401

Pure function tests — no I/O, no fixtures, no mocks.
Run with: pytest tests/test_auth_error_classifier.py -v
"""
from __future__ import annotations

import pytest

from _auth_error_classifier import classify_401


class TestRefreshable:
    def test_token_expired_in_body(self):
        v = classify_401(status=401, body='{"error":{"message":"token has expired"}}')
        assert v.category == "refreshable"
        assert v.reason == "token_expired"

    def test_access_token_expired_in_error_code(self):
        v = classify_401(status=401, body="", error_code="access_token_expired")
        assert v.category == "refreshable"
        assert v.reason == "access_token_expired"

    def test_generic_expired_word(self):
        v = classify_401(status=401, body='{"error":{"code":"expired"}}')
        assert v.category == "refreshable"
        assert v.reason == "generic_expired"

    def test_local_ttl_near_expiry_with_empty_body(self):
        v = classify_401(status=401, body="", token_near_expiry=True)
        assert v.category == "refreshable"
        assert v.reason == "local_ttl_near_expiry"


class TestReauth:
    @pytest.mark.parametrize(
        ("body", "expected_reason"),
        [
            ("OAuth token refresh failed", "oauth_refresh_failed"),
            ('{"error":{"code":"invalid_grant"}}', "invalid_grant"),
            ("invalid_refresh_token", "invalid_refresh_token"),
            ('{"error":{"message":"Invalid refresh token"}}', "invalid_refresh_token"),
            ("refresh_token_reused detected", "refresh_token_reused"),
            ("this token has been revoked", "token_revoked"),
            ("Please sign in again to continue", "sign_in_again"),
            ("missing scope: codex.read", "missing_scope"),
            ("insufficient_scopes for this request", "missing_scope"),
            ("OpenAI Codex scope is required", "codex_scope_missing"),
        ],
    )
    def test_reauth_patterns(self, body, expected_reason):
        v = classify_401(status=401, body=body)
        assert v.category == "reauth", f"expected reauth, got {v}"
        assert v.reason == expected_reason
        assert v.user_message

    def test_html_403_auth_page_cloudflare(self):
        html = (
            "<!DOCTYPE html><html><head><title>Just a moment...</title></head>"
            "<body>Cloudflare attention required. Please sign in.</body></html>"
        )
        v = classify_401(status=403, body=html)
        assert v.category == "reauth"
        assert v.reason == "html_403_auth_page"


class TestConfigErrors:
    @pytest.mark.parametrize(
        ("body", "expected_reason"),
        [
            ("Could not parse your authentication token", "unparseable_token"),
            ('No API key found for provider "openai"', "no_api_key_for_openai"),
            ("provider mismatch between request and credential", "provider_mismatch"),
            ("endpoint mismatch: got chat/completions, expected responses", "endpoint_mismatch"),
        ],
    )
    def test_config_patterns(self, body, expected_reason):
        v = classify_401(status=401, body=body)
        assert v.category == "config"
        assert v.reason == expected_reason
        assert v.user_message


class TestNonAuth:
    @pytest.mark.parametrize(
        ("body", "expected_reason"),
        [
            ("usage_limit_reached for this org", "usage_limit"),
            ("you are in cooldown, try later", "cooldown"),
            ("rate_limit exceeded", "rate_limit"),
            ("request timed out after 30s", "timeout"),
            ("fetch failed: ECONNRESET", "network"),
            ("pairing required before use", "pairing_required"),
        ],
    )
    def test_non_auth_patterns(self, body, expected_reason):
        v = classify_401(status=401, body=body)
        assert v.category == "non_auth"
        assert v.reason == expected_reason


class TestUnknown:
    def test_plain_401_no_signal(self):
        v = classify_401(status=401, body='{"error":{"message":"unauthorized"}}')
        assert v.category == "unknown"
        assert v.reason == "no_rule_matched"

    def test_empty_401(self):
        v = classify_401(status=401, body="")
        assert v.category == "unknown"


class TestRulePrecedence:
    def test_expired_plus_missing_scope_yields_reauth(self):
        body = "token has expired and missing scope: codex.read"
        v = classify_401(status=401, body=body)
        assert v.category == "reauth"
        assert v.reason == "missing_scope"

    def test_invalid_grant_plus_near_expiry_yields_reauth(self):
        v = classify_401(
            status=401,
            body='{"error":{"code":"invalid_grant"}}',
            token_near_expiry=True,
        )
        assert v.category == "reauth"
        assert v.reason == "invalid_grant"


class TestNon401Status:
    def test_500_returns_unknown(self):
        v = classify_401(status=500, body="internal server error")
        assert v.category == "unknown"
        assert v.reason == "status_500"

    def test_200_returns_unknown(self):
        v = classify_401(status=200, body="ok")
        assert v.category == "unknown"
        assert v.reason == "status_200"

    def test_403_without_html_is_not_reauth(self):
        v = classify_401(status=403, body='{"error":{"message":"forbidden"}}')
        assert v.category == "unknown"
        assert v.reason == "status_403"
