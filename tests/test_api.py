"""
test_api.py — Tests for all FastAPI endpoints.

Coverage:
  - Health endpoint
  - Company listing (with filter/search/pagination)
  - Company detail
  - Sitemap XML
  - robots.txt
  - llms.txt
  - JSON/CSV exports
  - Submission endpoint (rate limit, duplicate, success paths)
  - Admin endpoints (auth, elephant-verify, delete)
  - Static page routes
"""

import os
import re
import sqlite3
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def _add_company(conn: sqlite3.Connection, slug: str, domain: str, category: str = "aec", **kwargs) -> int:
    """Insert a minimal company row for testing."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO companies
            (slug, name, domain, category, submitted_at, status, elephant_verified, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'verified', 0, ?, ?)
        """,
        (slug, kwargs.get("name", slug), domain, category, now, now, now),
    )
    conn.commit()
    return conn.execute("SELECT id FROM companies WHERE slug = ?", (slug,)).fetchone()["id"]


def _add_surface(conn: sqlite3.Connection, company_id: int, surface: str, verified: bool) -> None:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO surface_status (company_id, surface, verified, last_checked_at)
        VALUES (?, ?, ?, ?)
        """,
        (company_id, surface, int(verified), now),
    )
    conn.commit()


# ===========================================================================
# Health endpoint
# ===========================================================================
class TestHealth:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_health_has_counts(self, client):
        resp = client.get("/health")
        data = resp.json()
        assert "counts" in data
        assert "total" in data["counts"]
        assert "verified" in data["counts"]
        assert "pending" in data["counts"]

    def test_health_counts_seeded_companies(self, client):
        resp = client.get("/health")
        data = resp.json()
        # Seed inserts 10 companies
        assert data["counts"]["total"] == 10


# ===========================================================================
# Company listing
# ===========================================================================
class TestCompanyList:
    def test_list_returns_companies(self, client):
        resp = client.get("/api/companies")
        assert resp.status_code == 200
        data = resp.json()
        assert "companies" in data
        assert len(data["companies"]) > 0

    def test_list_has_total(self, client):
        resp = client.get("/api/companies")
        data = resp.json()
        assert "total" in data
        assert data["total"] == 10

    def test_list_filter_by_category(self, client):
        resp = client.get("/api/companies?category=aec")
        data = resp.json()
        for c in data["companies"]:
            assert c["category"] == "aec"

    def test_list_filter_consulting(self, client):
        resp = client.get("/api/companies?category=consulting")
        data = resp.json()
        assert data["total"] >= 1
        names = [c["name"] for c in data["companies"]]
        assert any("Elephant" in n for n in names)

    def test_list_search_by_name(self, client):
        resp = client.get("/api/companies?q=Bentley")
        data = resp.json()
        assert data["total"] >= 1
        assert any("Bentley" in c["name"] for c in data["companies"])

    def test_list_search_by_domain(self, client):
        resp = client.get("/api/companies?q=procore.com")
        data = resp.json()
        assert data["total"] >= 1

    def test_list_pagination_limit(self, client):
        resp = client.get("/api/companies?limit=3")
        data = resp.json()
        assert len(data["companies"]) <= 3
        assert data["limit"] == 3

    def test_list_pagination_offset(self, client):
        resp_all = client.get("/api/companies?limit=10&offset=0")
        resp_offset = client.get("/api/companies?limit=10&offset=5")
        all_slugs = [c["slug"] for c in resp_all.json()["companies"]]
        offset_slugs = [c["slug"] for c in resp_offset.json()["companies"]]
        # offset results should be different
        assert offset_slugs != all_slugs[:5]

    def test_list_includes_surfaces(self, client):
        resp = client.get("/api/companies")
        data = resp.json()
        c = data["companies"][0]
        assert "surfaces" in c

    def test_list_no_deleted_companies(self, client, seeded_db):
        # Soft-delete a company and verify it's not returned
        seeded_db.execute(
            "UPDATE companies SET status = 'deleted' WHERE slug = 'procore'"
        )
        seeded_db.commit()
        resp = client.get("/api/companies")
        slugs = [c["slug"] for c in resp.json()["companies"]]
        assert "procore" not in slugs


# ===========================================================================
# Company detail
# ===========================================================================
class TestCompanyDetail:
    def test_get_company_exists(self, client):
        resp = client.get("/api/companies/procore")
        assert resp.status_code == 200
        data = resp.json()
        assert data["slug"] == "procore"
        assert data["domain"] == "procore.com"

    def test_get_company_has_surfaces(self, client):
        resp = client.get("/api/companies/procore")
        data = resp.json()
        assert "surfaces" in data
        assert isinstance(data["surfaces"], list)

    def test_get_company_not_found(self, client):
        resp = client.get("/api/companies/does-not-exist-xyz")
        assert resp.status_code == 404

    def test_get_elephant_verified_company(self, client):
        resp = client.get("/api/companies/elephant-accountability")
        data = resp.json()
        assert data["elephant_verified"] == 1


# ===========================================================================
# Sitemap
# ===========================================================================
class TestSitemap:
    def test_sitemap_returns_xml(self, client):
        resp = client.get("/sitemap.xml")
        assert resp.status_code == 200
        assert "xml" in resp.headers["content-type"]

    def test_sitemap_has_company_urls(self, client):
        resp = client.get("/sitemap.xml")
        text = resp.text
        # Should have at least 10 company URLs from seed
        assert text.count("/company/") >= 10

    def test_sitemap_valid_xml_structure(self, client):
        resp = client.get("/sitemap.xml")
        assert "<?xml" in resp.text
        assert "<urlset" in resp.text
        assert "</urlset>" in resp.text


# ===========================================================================
# robots.txt
# ===========================================================================
class TestRobots:
    def test_robots_returns_ok(self, client):
        resp = client.get("/robots.txt")
        assert resp.status_code == 200

    def test_robots_allows_all(self, client):
        resp = client.get("/robots.txt")
        assert "Allow: /" in resp.text

    def test_robots_has_sitemap(self, client):
        resp = client.get("/robots.txt")
        assert "Sitemap:" in resp.text

    def test_robots_disallows_admin(self, client):
        resp = client.get("/robots.txt")
        assert "Disallow: /api/admin/" in resp.text


# ===========================================================================
# llms.txt
# ===========================================================================
class TestLlmsTxt:
    def test_llms_txt_returns_ok(self, client):
        resp = client.get("/llms.txt")
        assert resp.status_code == 200

    def test_llms_txt_has_header(self, client):
        resp = client.get("/llms.txt")
        assert "# Agent-Ready Directory" in resp.text

    def test_llms_txt_lists_companies(self, client):
        resp = client.get("/llms.txt")
        # Should list seeded companies
        assert "Procore" in resp.text or "procore" in resp.text

    def test_llms_txt_mentions_surfaces(self, client):
        resp = client.get("/llms.txt")
        assert "llms.txt" in resp.text.lower()
        assert "MCP" in resp.text


# ===========================================================================
# Export
# ===========================================================================
class TestExport:
    def test_json_export(self, client):
        resp = client.get("/api/export.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "companies" in data
        assert len(data["companies"]) > 0

    def test_csv_export(self, client):
        resp = client.get("/api/export.csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        lines = resp.text.strip().split("\n")
        # Header + at least 10 data rows
        assert len(lines) >= 11

    def test_csv_has_correct_headers(self, client):
        resp = client.get("/api/export.csv")
        header = resp.text.split("\n")[0]
        assert "slug" in header
        assert "name" in header
        assert "domain" in header
        assert "llms_txt" in header


# ===========================================================================
# Static pages
# ===========================================================================
class TestStaticPages:
    def test_index_serves_html(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_submit_page(self, client):
        resp = client.get("/submit")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_about_page(self, client):
        resp = client.get("/about")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_company_page_slug(self, client):
        resp = client.get("/company/procore")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]


# ===========================================================================
# Submissions
# ===========================================================================
class TestSubmissions:
    def test_submission_duplicate_domain(self, client):
        """Submitting an already-listed domain should return 409."""
        resp = client.post("/api/submissions", json={
            "domain": "procore.com",
            "company_name": "Procore Again",
            "category": "aec",
        })
        assert resp.status_code == 409

    def test_submission_rate_limit(self, client, seeded_db):
        """More than 3 submissions from the same IP in 24h should return 429."""
        from datetime import datetime, timezone
        from app.server import _hash_ip
        # Pre-seed three submissions whose ip_hash matches what the server will
        # compute for the TestClient request below. _hash_ip is HMAC-keyed so
        # we must use the same helper here, not raw sha256.
        ip_hash = _hash_ip("testclient")
        now = datetime.now(timezone.utc).isoformat()
        for i in range(3):
            seeded_db.execute(
                "INSERT INTO submissions (domain, company_name, submitted_at, ip_hash) VALUES (?, ?, ?, ?)",
                (f"test{i}.com", f"Test {i}", now, ip_hash),
            )
        seeded_db.commit()

        # Next submission should be rate-limited
        resp = client.post("/api/submissions", json={
            "domain": "newdomain99.com",
            "company_name": "New Co",
            "category": "aec",
        })
        assert resp.status_code == 429

    @patch("app.server._is_public_hostname", return_value=True)
    @patch("app.server._check_llms_txt", new_callable=AsyncMock)
    @patch("app.server._check_mcp", new_callable=AsyncMock)
    @patch("app.server._check_a2a", new_callable=AsyncMock)
    @patch("app.server._check_ucp", new_callable=AsyncMock)
    @patch("app.server._check_schema_org", new_callable=AsyncMock)
    def test_submission_pending_if_surface_found(
        self,
        mock_schema, mock_ucp, mock_a2a, mock_mcp, mock_llms, mock_public,
        client
    ):
        """Even if a surface is detected, the row lands as 'pending'.

        Brand-hijack fix: an attacker who controls evil.com could otherwise
        publish /.well-known/mcp.json with {"name":"Microsoft"} and
        self-publish a verified row. Detection still records the surfaces but
        status='pending' until an admin promotes it.
        """
        mock_llms.return_value = (True, "https://newco.io/llms.txt")
        mock_mcp.return_value = (False, None)
        mock_a2a.return_value = (False, None)
        mock_ucp.return_value = (False, None)
        mock_schema.return_value = (False, None)

        resp = client.post("/api/submissions", json={
            "domain": "newco.io",
            "company_name": "New Co",
            "category": "fintech",
        })
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "pending"
        assert data["surfaces"]["llms_txt"] is True

    @patch("app.server._is_public_hostname", return_value=True)
    @patch("app.server._check_llms_txt", new_callable=AsyncMock)
    @patch("app.server._check_mcp", new_callable=AsyncMock)
    @patch("app.server._check_a2a", new_callable=AsyncMock)
    @patch("app.server._check_ucp", new_callable=AsyncMock)
    @patch("app.server._check_schema_org", new_callable=AsyncMock)
    def test_submission_pending_if_no_surface(
        self,
        mock_schema, mock_ucp, mock_a2a, mock_mcp, mock_llms, mock_public,
        client
    ):
        """If no surface found, status is still 'pending' (same as detected)."""
        mock_llms.return_value = (False, None)
        mock_mcp.return_value = (False, None)
        mock_a2a.return_value = (False, None)
        mock_ucp.return_value = (False, None)
        mock_schema.return_value = (False, None)

        resp = client.post("/api/submissions", json={
            "domain": "nothinghere99.io",
            "company_name": "Ghost Co",
            "category": "other",
        })
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "pending"


# ===========================================================================
# Admin endpoints
# ===========================================================================
class TestAdmin:
    def test_admin_requires_auth(self, client):
        resp = client.post("/api/admin/verify-all")
        assert resp.status_code == 403

    def test_admin_wrong_token(self, client):
        resp = client.post(
            "/api/admin/verify-all",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 403

    def test_admin_elephant_verify_toggle(self, client, seeded_db):
        os.environ["ADMIN_TOKEN"] = "test-token-xyz"
        try:
            # procore starts as elephant_verified=0
            resp = client.post(
                "/api/admin/companies/procore/elephant-verify",
                headers={"Authorization": "Bearer test-token-xyz"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["elephant_verified"] is True

            # Toggle back
            resp2 = client.post(
                "/api/admin/companies/procore/elephant-verify",
                headers={"Authorization": "Bearer test-token-xyz"},
            )
            assert resp2.json()["elephant_verified"] is False
        finally:
            del os.environ["ADMIN_TOKEN"]

    def test_admin_delete_company(self, client, seeded_db):
        os.environ["ADMIN_TOKEN"] = "test-token-xyz"
        try:
            resp = client.delete(
                "/api/admin/companies/procore",
                headers={"Authorization": "Bearer test-token-xyz"},
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "deleted"

            # Should no longer appear in listing
            list_resp = client.get("/api/companies")
            slugs = [c["slug"] for c in list_resp.json()["companies"]]
            assert "procore" not in slugs
        finally:
            del os.environ["ADMIN_TOKEN"]

    def test_admin_delete_not_found(self, client):
        os.environ["ADMIN_TOKEN"] = "test-token-xyz"
        try:
            resp = client.delete(
                "/api/admin/companies/does-not-exist",
                headers={"Authorization": "Bearer test-token-xyz"},
            )
            assert resp.status_code == 404
        finally:
            del os.environ["ADMIN_TOKEN"]
