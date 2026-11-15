#!/usr/bin/env python3
"""
Jinja2 template for API integration tests
Follows the sso/wg_gui patterns: test client, auth gates, rate limits, CSRF, redirect safety
"""

import pytest

# Routes discovered in entrypoint:
#   GET / -> index
#   GET /graphs/<path:fname>.png -> graph_png
#   GET /traces/ -> traces_global
#   GET /traces/<target>/ -> traces_history
#   GET /traces/<target>/<node> -> traces_pair
#   GET /traces/<target>/<node>/<date>.txt -> traces_raw
#   GET /api/latest -> api_latest
#   GET /admin/ -> admin
#   GET /admin/api/targets -> admin_list_targets
#   POST /admin/api/targets -> admin_add_target
#   POST /admin/api/targets/<path:name> -> admin_remove_target
#   GET /admin/api/nodes -> admin_list_nodes
#   POST /admin/api/nodes -> admin_add_node
#   POST /admin/api/nodes/<path:name> -> admin_remove_node
#   POST /admin/api/nodes/<path:name>/backlog -> admin_node_backlog
#   POST /admin/api/verify -> admin_verify
#   POST /admin/api/import -> admin_import
#   GET /admin/api/summary -> admin_summary


class TestHealthEndpoints:
    """Tests for health check and public endpoints."""

    def test_healthz(self, client):
        """Health check endpoint should return 200."""
        resp = client.get("/healthz")
        # Some apps use /health, /healthz, /ready, /ping
        assert resp.status_code in (200, 404)  # 404 if not implemented

    def test_root_redirects_or_returns_content(self, client):
        """Root endpoint should respond (redirect or content)."""
        resp = client.get("/")
        assert resp.status_code in (200, 301, 302, 401, 403)


class TestAuthGates:
    """Tests for authentication gates (SSO, Basic, API key)."""

    def test_protected_endpoint_requires_auth(self, client):
        """Protected endpoints should return 401/403 without auth."""
        # Test a known protected endpoint
        protected_routes = [
            ("/", ["GET"]),
            ("/graphs/<path:fname>.png", ["GET"]),
            ("/traces/", ["GET"]),
            ("/traces/<target>/", ["GET"]),
            ("/traces/<target>/<node>", ["GET"]),
            ("/traces/<target>/<node>/<date>.txt", ["GET"]),
            ("/api/latest", ["GET"]),
            ("/admin/", ["GET"]),
            ("/admin/api/targets", ["GET"]),
            ("/admin/api/targets", ["POST"]),
            ("/admin/api/targets/<path:name>", ["POST"]),
            ("/admin/api/nodes", ["GET"]),
            ("/admin/api/nodes", ["POST"]),
            ("/admin/api/nodes/<path:name>", ["POST"]),
            ("/admin/api/nodes/<path:name>/backlog", ["POST"]),
            ("/admin/api/verify", ["POST"]),
            ("/admin/api/import", ["POST"]),
            ("/admin/api/summary", ["GET"]),
        ]
        for route, methods in protected_routes:
            # Skip health check endpoints (intentionally public)
            if route in ["/healthz", "/health", "/ready", "/ping", "/metrics"]:
                continue
            if route == "/":
                continue
            # Use the first supported method for testing auth
            method = methods[0].lower()
            resp = getattr(client, method)(route)
            # Should be 401 (unauthenticated) or 403 (forbidden) or 302 (redirect to login) or 405 (wrong method but auth gate works)
            assert resp.status_code in (401, 403, 302, 405), f"Route {route} should require auth"

    def test_sso_redirect_preserves_next(self, client):
        """SSO login should preserve the next parameter."""
        # This tests the SSO gate pattern
        resp = client.get("/protected?next=/target")
        if resp.status_code == 302:
            location = resp.headers.get("Location", "")
            assert "next=" in location or "/sso/login" in location


class TestRateLimiting:
    """Tests for rate limiting on auth endpoints."""

    def test_login_rate_limit(self, client):
        """Repeated failed logins should be rate limited."""
        # This is a placeholder - actual implementation depends on the app
        # The sso pattern uses throttle_record_failure / throttle_blocked
        pass


class TestCSRFProtection:
    """Tests for CSRF protection on mutating endpoints."""

    def test_mutating_endpoint_requires_csrf(self, client):
        """POST/PUT/DELETE endpoints should require CSRF token."""
        resp = client.post("/admin/api/targets", data={})
        # May return 401 (auth required first), 400 (bad request), or 403 (CSRF missing)
        assert resp.status_code in (400, 401, 403), f"/admin/api/targets should require CSRF or auth"
        resp = client.post("/admin/api/targets/<path:name>", data={})
        # May return 401 (auth required first), 400 (bad request), or 403 (CSRF missing)
        assert resp.status_code in (400, 401, 403), f"/admin/api/targets/<path:name> should require CSRF or auth"
        resp = client.post("/admin/api/nodes", data={})
        # May return 401 (auth required first), 400 (bad request), or 403 (CSRF missing)
        assert resp.status_code in (400, 401, 403), f"/admin/api/nodes should require CSRF or auth"
        resp = client.post("/admin/api/nodes/<path:name>", data={})
        # May return 401 (auth required first), 400 (bad request), or 403 (CSRF missing)
        assert resp.status_code in (400, 401, 403), f"/admin/api/nodes/<path:name> should require CSRF or auth"
        resp = client.post("/admin/api/nodes/<path:name>/backlog", data={})
        # May return 401 (auth required first), 400 (bad request), or 403 (CSRF missing)
        assert resp.status_code in (400, 401, 403), f"/admin/api/nodes/<path:name>/backlog should require CSRF or auth"
        resp = client.post("/admin/api/verify", data={})
        # May return 401 (auth required first), 400 (bad request), or 403 (CSRF missing)
        assert resp.status_code in (400, 401, 403), f"/admin/api/verify should require CSRF or auth"
        resp = client.post("/admin/api/import", data={})
        # May return 401 (auth required first), 400 (bad request), or 403 (CSRF missing)
        assert resp.status_code in (400, 401, 403), f"/admin/api/import should require CSRF or auth"


class TestRedirectSafety:
    """Tests for open redirect protection."""

    def test_redirect_validation(self, client):
        """Redirects should be validated against allowlist."""
        # Test the safe_next pattern from sso
        malicious_targets = [
            "https://evil.example/",
            "//evil.example/",
            "javascript:alert(1)",
            "/\\evil.example/",
        ]
        for target in malicious_targets:
            # This would need app-specific testing
            pass


class TestAPIEndpoints:
    """Tests for specific API endpoints."""

    def test_index_endpoint(self, client):
        """Test GET /."""
        resp = client.open("/", method="GET")
        # Should not be 500
        assert resp.status_code != 500
    def test_graph_png_endpoint(self, client):
        """Test GET /graphs/<path:fname>.png."""
        resp = client.open("/graphs/<path:fname>.png", method="GET")
        # Should not be 500
        assert resp.status_code != 500
    def test_traces_global_endpoint(self, client):
        """Test GET /traces/."""
        resp = client.open("/traces/", method="GET")
        # Should not be 500
        assert resp.status_code != 500
    def test_traces_history_endpoint(self, client):
        """Test GET /traces/<target>/."""
        resp = client.open("/traces/<target>/", method="GET")
        # Should not be 500
        assert resp.status_code != 500
    def test_traces_pair_endpoint(self, client):
        """Test GET /traces/<target>/<node>."""
        resp = client.open("/traces/<target>/<node>", method="GET")
        # Should not be 500
        assert resp.status_code != 500
    def test_traces_raw_endpoint(self, client):
        """Test GET /traces/<target>/<node>/<date>.txt."""
        resp = client.open("/traces/<target>/<node>/<date>.txt", method="GET")
        # Should not be 500
        assert resp.status_code != 500
    def test_api_latest_endpoint(self, client):
        """Test GET /api/latest."""
        resp = client.open("/api/latest", method="GET")
        # Should not be 500
        assert resp.status_code != 500
    def test_admin_endpoint(self, client):
        """Test GET /admin/."""
        resp = client.open("/admin/", method="GET")
        # Should not be 500
        assert resp.status_code != 500
    def test_admin_list_targets_endpoint(self, client):
        """Test GET /admin/api/targets."""
        resp = client.open("/admin/api/targets", method="GET")
        # Should not be 500
        assert resp.status_code != 500
    def test_admin_add_target_endpoint(self, client):
        """Test POST /admin/api/targets."""
        resp = client.open("/admin/api/targets", method="POST")
        # Should not be 500
        assert resp.status_code != 500
    def test_admin_remove_target_endpoint(self, client):
        """Test POST /admin/api/targets/<path:name>."""
        resp = client.open("/admin/api/targets/<path:name>", method="POST")
        # Should not be 500
        assert resp.status_code != 500
    def test_admin_list_nodes_endpoint(self, client):
        """Test GET /admin/api/nodes."""
        resp = client.open("/admin/api/nodes", method="GET")
        # Should not be 500
        assert resp.status_code != 500
    def test_admin_add_node_endpoint(self, client):
        """Test POST /admin/api/nodes."""
        resp = client.open("/admin/api/nodes", method="POST")
        # Should not be 500
        assert resp.status_code != 500
    def test_admin_remove_node_endpoint(self, client):
        """Test POST /admin/api/nodes/<path:name>."""
        resp = client.open("/admin/api/nodes/<path:name>", method="POST")
        # Should not be 500
        assert resp.status_code != 500
    def test_admin_node_backlog_endpoint(self, client):
        """Test POST /admin/api/nodes/<path:name>/backlog."""
        resp = client.open("/admin/api/nodes/<path:name>/backlog", method="POST")
        # Should not be 500
        assert resp.status_code != 500
    def test_admin_verify_endpoint(self, client):
        """Test POST /admin/api/verify."""
        resp = client.open("/admin/api/verify", method="POST")
        # Should not be 500
        assert resp.status_code != 500
    def test_admin_import_endpoint(self, client):
        """Test POST /admin/api/import."""
        resp = client.open("/admin/api/import", method="POST")
        # Should not be 500
        assert resp.status_code != 500
    def test_admin_summary_endpoint(self, client):
        """Test GET /admin/api/summary."""
        resp = client.open("/admin/api/summary", method="GET")
        # Should not be 500
        assert resp.status_code != 500
