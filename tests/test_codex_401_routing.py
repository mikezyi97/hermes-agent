"""
Regression tests for run_agent._decide_codex_auth_action.

Pure synchronous tests — no mocks, no I/O, no fixtures.
"""
from __future__ import annotations

import sys
import types

import pytest

sys.modules.setdefault("fire", types.SimpleNamespace(Fire=lambda *a, **k: None))
sys.modules.setdefault("firecrawl", types.SimpleNamespace(Firecrawl=object))
sys.modules.setdefault("fal_client", types.SimpleNamespace())

from run_agent import _decide_codex_auth_action


class TestRefreshable:
    def test_token_expired_triggers_refresh_then_retry(self):
        action = _decide_codex_auth_action(
            status=401,
            body='{"error":{"message":"token has expired"}}',
            error_code=None,
        )
        assert action.kind == "refresh_then_retry"
        assert action.skip_pool_recovery is False

    def test_access_token_expired_triggers_refresh_then_retry(self):
        action = _decide_codex_auth_action(
            status=401,
            body="",
            error_code="access_token_expired",
        )
        assert action.kind == "refresh_then_retry"
        assert action.skip_pool_recovery is False


class TestReauth:
    @pytest.mark.parametrize(
        "body",
        [
            "OAuth token refresh failed",
            '{"error":{"code":"invalid_grant"}}',
            "refresh_token_reused detected",
            "token has been revoked",
            "Please sign in again",
            "missing scope: codex.read",
        ],
    )
    def test_reauth_never_refreshes_and_skips_pool(self, body):
        action = _decide_codex_auth_action(status=401, body=body, error_code=None)
        assert action.kind == "reauth_passthrough"
        assert action.skip_pool_recovery is True
        assert action.user_message

    def test_html_403_cloudflare_is_reauth(self):
        html = "<!DOCTYPE html><html><body>Cloudflare attention required. Please sign in.</body></html>"
        action = _decide_codex_auth_action(status=403, body=html, error_code=None)
        assert action.kind == "reauth_passthrough"
        assert action.skip_pool_recovery is True


class TestConfig:
    @pytest.mark.parametrize(
        "body",
        [
            "Could not parse your authentication token",
            'No API key found for provider "openai"',
        ],
    )
    def test_config_never_refreshes_and_skips_pool(self, body):
        action = _decide_codex_auth_action(status=401, body=body, error_code=None)
        assert action.kind == "config_passthrough"
        assert action.skip_pool_recovery is True
        assert action.user_message


class TestNonAuth:
    def test_rate_limit_is_passthrough_and_allows_pool_recovery(self):
        action = _decide_codex_auth_action(
            status=401,
            body="rate_limit exceeded",
            error_code=None,
        )
        assert action.kind == "passthrough"
        assert action.skip_pool_recovery is False

    def test_network_error_is_passthrough_and_allows_pool_recovery(self):
        action = _decide_codex_auth_action(
            status=401,
            body="fetch failed: ECONNRESET",
            error_code=None,
        )
        assert action.kind == "passthrough"
        assert action.skip_pool_recovery is False

    def test_pairing_required_is_passthrough_but_skips_pool(self):
        action = _decide_codex_auth_action(
            status=401,
            body="pairing required",
            error_code=None,
        )
        assert action.kind == "passthrough"
        assert action.skip_pool_recovery is True
        assert action.verdict_reason == "pairing_required"


class TestUnknownDoesNotRefresh:
    def test_plain_401_does_not_trigger_refresh(self):
        action = _decide_codex_auth_action(
            status=401,
            body='{"error":{"message":"unauthorized"}}',
            error_code=None,
        )
        assert action.kind == "unknown_passthrough"
        assert action.skip_pool_recovery is True
        assert action.kind != "refresh_then_retry"

    def test_empty_401_does_not_trigger_refresh(self):
        action = _decide_codex_auth_action(status=401, body="", error_code=None)
        assert action.kind == "unknown_passthrough"
        assert action.kind != "refresh_then_retry"


class TestPrecedence:
    def test_expired_plus_missing_scope_does_not_refresh(self):
        action = _decide_codex_auth_action(
            status=401,
            body="token has expired and missing scope: codex.read",
            error_code=None,
        )
        assert action.kind == "reauth_passthrough"
        assert action.skip_pool_recovery is True
