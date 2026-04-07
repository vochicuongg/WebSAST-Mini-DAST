"""
tests/test_discovery_scanner.py
Unit tests cho DiscoveryScanner — toan bo HTTP calls duoc mock.
"""
import pytest
import requests
from unittest.mock import patch, MagicMock
from scanner_discovery import DiscoveryScanner, FormInfo

BASE = "http://test.local"


# ─── Helpers ─────────────────────────────────────────────────────────────────

def make_resp(body="", status_code=200, headers=None):
    mock = MagicMock()
    mock.text = body
    mock.status_code = status_code
    mock.headers = {"Content-Type": "text/html", **(headers or {})}
    return mock


@pytest.fixture
def ds():
    """Fixture tao DiscoveryScanner voi session mock."""
    mock_session = MagicMock()
    mock_session.cookies = MagicMock()
    scanner = DiscoveryScanner(BASE, mock_session, max_pages=5, timeout=5)
    return scanner, mock_session


# ─── Crawl & Form Discovery ──────────────────────────────────────────────────

class TestDiscoveryCrawl:
    def test_crawl_excludes_external_domains(self, ds):
        scanner, mock_session = ds
        html = '<html><body><a href="https://evil.com/hack">Evil</a><a href="/safe">Safe</a></body></html>'
        mock_session.get.return_value = make_resp(html)
        urls = scanner.crawl_site()
        assert "https://evil.com/hack" not in urls

    def test_crawl_includes_same_domain_links(self, ds):
        scanner, mock_session = ds
        html = '<html><body><a href="/page1">P1</a></body></html>'
        mock_session.get.return_value = make_resp(html)
        urls = scanner.crawl_site()
        assert BASE in urls

    def test_fetch_forms_extracts_post_forms(self, ds):
        scanner, mock_session = ds
        html = (
            '<html><body><form action="/login" method="POST">'
            '<input name="username" type="text">'
            '<input name="password" type="password">'
            '</form></body></html>'
        )
        mock_session.get.return_value = make_resp(html)
        forms = scanner.fetch_all_forms({BASE})
        assert len(forms) == 1
        assert forms[0].method == "POST"
        assert any(f["name"] == "username" for f in forms[0].fields)

    def test_fetch_forms_skips_pages_without_forms(self, ds):
        scanner, mock_session = ds
        mock_session.get.return_value = make_resp("<html><body><p>No forms</p></body></html>")
        forms = scanner.fetch_all_forms({BASE})
        assert len(forms) == 0

    def test_fetch_forms_multiple_forms(self, ds):
        scanner, mock_session = ds
        html = (
            '<html><body>'
            '<form action="/login" method="POST"><input name="user"></form>'
            '<form action="/search" method="GET"><input name="q"></form>'
            '</body></html>'
        )
        mock_session.get.return_value = make_resp(html)
        forms = scanner.fetch_all_forms({BASE})
        assert len(forms) == 2


# ─── D-01: SQLi Generic ──────────────────────────────────────────────────────

class TestDiscoverySQLi:
    def test_passed_no_sql_error(self, ds):
        scanner, mock_session = ds
        mock_session.get.return_value = make_resp("Normal search results")
        forms = [FormInfo(BASE, f"{BASE}/search", "GET",
                          [{"name": "q", "type": "text", "value": ""}])]
        result = scanner.test_sqli_generic(forms)
        assert result.vuln_id == "D-01"
        assert result.status == "PASSED"
        assert result.severity == "CRITICAL"

    def test_failed_mysqli_error_in_response(self, ds):
        scanner, mock_session = ds
        mock_session.get.return_value = make_resp(
            "Warning: mysqli_fetch_array() expects parameter 1 to be mysqli_result")
        forms = [FormInfo(BASE, f"{BASE}/search", "GET",
                          [{"name": "q", "type": "text", "value": ""}])]
        result = scanner.test_sqli_generic(forms)
        assert result.status == "FAILED"
        assert result.severity == "CRITICAL"

    def test_failed_sql_syntax_error_in_response(self, ds):
        scanner, mock_session = ds
        mock_session.post.return_value = make_resp(
            "You have an error in your sql syntax near WHERE id='")
        forms = [FormInfo(BASE, f"{BASE}/login", "POST",
                          [{"name": "username", "type": "text", "value": ""}])]
        result = scanner.test_sqli_generic(forms)
        assert result.status == "FAILED"

    def test_passed_empty_forms(self, ds):
        scanner, _ = ds
        assert scanner.test_sqli_generic([]).status == "PASSED"

    def test_skips_submit_button_fields(self, ds):
        scanner, mock_session = ds
        mock_session.get.return_value = make_resp("Normal page")
        forms = [FormInfo(BASE, f"{BASE}/x", "GET",
                          [{"name": "sub", "type": "submit", "value": "Submit"}])]
        result = scanner.test_sqli_generic(forms)
        assert result.status == "PASSED"


# ─── D-02: XSS Generic ───────────────────────────────────────────────────────

class TestDiscoveryXSS:
    XSS = "<script>alert('XSS_DAST_GENERIC')</script>"

    def test_passed_payload_encoded(self, ds):
        scanner, mock_session = ds
        mock_session.post.return_value = make_resp("&lt;script&gt;alert(1)&lt;/script&gt;")
        forms = [FormInfo(BASE, f"{BASE}/submit", "POST",
                          [{"name": "q", "type": "text", "value": ""}])]
        assert scanner.test_xss_generic(forms).status == "PASSED"

    def test_failed_payload_reflected_raw(self, ds):
        scanner, mock_session = ds
        mock_session.post.return_value = make_resp(
            f"<p>You searched: {self.XSS}</p>")
        forms = [FormInfo(BASE, f"{BASE}/submit", "POST",
                          [{"name": "q", "type": "text", "value": ""}])]
        result = scanner.test_xss_generic(forms)
        assert result.status == "FAILED"
        assert result.severity == "HIGH"

    def test_passed_empty_forms(self, ds):
        scanner, _ = ds
        assert scanner.test_xss_generic([]).status == "PASSED"

    def test_skips_hidden_fields(self, ds):
        scanner, mock_session = ds
        mock_session.post.return_value = make_resp("safe")
        forms = [FormInfo(BASE, f"{BASE}/x", "POST",
                          [{"name": "tok", "type": "hidden", "value": "abc"}])]
        assert scanner.test_xss_generic(forms).status == "PASSED"


# ─── D-03: CSRF Generic ──────────────────────────────────────────────────────

class TestDiscoveryCSRF:
    def test_skipped_no_post_forms(self, ds):
        scanner, _ = ds
        forms = [FormInfo(BASE, f"{BASE}/s", "GET",
                          [{"name": "q", "type": "text", "value": ""}])]
        assert scanner.test_csrf_generic(forms).status == "SKIPPED"

    def test_failed_no_csrf_token(self, ds):
        scanner, _ = ds
        forms = [FormInfo(BASE, f"{BASE}/add", "POST",
                          [{"name": "name", "type": "text", "value": ""},
                           {"name": "email", "type": "email", "value": ""}])]
        result = scanner.test_csrf_generic(forms)
        assert result.status == "FAILED"
        assert result.severity == "HIGH"

    def test_passed_has_csrf_token(self, ds):
        scanner, _ = ds
        forms = [FormInfo(BASE, f"{BASE}/add", "POST",
                          [{"name": "name", "type": "text", "value": ""},
                           {"name": "csrf_token", "type": "hidden", "value": "abc123"}])]
        assert scanner.test_csrf_generic(forms).status == "PASSED"

    def test_passed_has_underscore_token(self, ds):
        scanner, _ = ds
        forms = [FormInfo(BASE, f"{BASE}/edit", "POST",
                          [{"name": "data", "type": "text", "value": ""},
                           {"name": "_token", "type": "hidden", "value": "xyz"}])]
        assert scanner.test_csrf_generic(forms).status == "PASSED"


# ─── D-05: Security Headers ──────────────────────────────────────────────────

class TestDiscoverySecurityHeaders:
    ALL_HEADERS = {
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000",
        "Referrer-Policy": "no-referrer",
    }

    def test_passed_all_headers_present(self, ds):
        scanner, _ = ds
        with patch("scanner_discovery.requests.get",
                   return_value=make_resp("", headers=self.ALL_HEADERS)):
            assert scanner.test_security_headers().status == "PASSED"

    def test_failed_missing_3_or_more_headers(self, ds):
        scanner, _ = ds
        with patch("scanner_discovery.requests.get",
                   return_value=make_resp("", headers={"Server": "Apache"})):
            result = scanner.test_security_headers()
        assert result.status == "FAILED"
        assert result.severity == "MEDIUM"
        assert "MEDIUM" == result.severity

    def test_connection_error(self, ds):
        scanner, _ = ds
        with patch("scanner_discovery.requests.get",
                   side_effect=requests.exceptions.ConnectionError()):
            assert scanner.test_security_headers().status == "ERROR"


# ─── D-06: Cookie Flags ──────────────────────────────────────────────────────

class TestDiscoveryCookieFlags:
    def test_failed_missing_httponly(self, ds):
        scanner, _ = ds
        cookie_header = "PHPSESSID=abc123; path=/; Secure; SameSite=Strict"
        with patch("scanner_discovery.requests.post",
                   return_value=make_resp("", headers={"Set-Cookie": cookie_header})):
            result = scanner.test_cookie_flags()
        assert result.status == "FAILED"
        assert "HttpOnly" in result.evidence

    def test_failed_all_flags_missing(self, ds):
        scanner, _ = ds
        cookie_header = "PHPSESSID=abc123; path=/"
        with patch("scanner_discovery.requests.post",
                   return_value=make_resp("", headers={"Set-Cookie": cookie_header})):
            result = scanner.test_cookie_flags()
        assert result.status == "FAILED"

    def test_passed_all_flags_present(self, ds):
        scanner, _ = ds
        cookie_header = "PHPSESSID=abc123; HttpOnly; Secure; SameSite=Strict; path=/"
        with patch("scanner_discovery.requests.post",
                   return_value=make_resp("", headers={"Set-Cookie": cookie_header})):
            result = scanner.test_cookie_flags()
        assert result.status == "PASSED"


# ─── D-07: Sensitive Files ───────────────────────────────────────────────────

class TestDiscoverySensitiveFiles:
    def test_passed_all_return_404(self, ds):
        scanner, _ = ds
        with patch("scanner_discovery.requests.get",
                   return_value=make_resp("Page Not Found", status_code=404)):
            assert scanner.test_sensitive_files().status == "PASSED"

    def test_failed_git_head_exposed(self, ds):
        scanner, _ = ds
        def side_effect(url, **kwargs):
            if ".git/HEAD" in url:
                return make_resp("ref: refs/heads/main", status_code=200)
            return make_resp("Not Found", status_code=404)
        with patch("scanner_discovery.requests.get", side_effect=side_effect):
            result = scanner.test_sensitive_files()
        assert result.status == "FAILED"
        assert result.severity == "CRITICAL"

    def test_failed_phpinfo_exposed(self, ds):
        scanner, _ = ds
        def side_effect(url, **kwargs):
            if "phpinfo.php" in url:
                return make_resp("PHP Version 8.1.20 phpinfo()", status_code=200)
            return make_resp("Not Found", status_code=404)
        with patch("scanner_discovery.requests.get", side_effect=side_effect):
            assert scanner.test_sensitive_files().status == "FAILED"


# ─── D-08: Directory Listing ─────────────────────────────────────────────────

class TestDiscoveryDirectoryListing:
    def test_passed_no_listing(self, ds):
        scanner, _ = ds
        with patch("scanner_discovery.requests.get",
                   return_value=make_resp("Forbidden", status_code=403)):
            assert scanner.test_directory_listing().status == "PASSED"

    def test_failed_index_of(self, ds):
        scanner, _ = ds
        html = "<html><title>Index of /uploads/</title><body>Index of /uploads/ Parent Directory file.txt</body></html>"
        with patch("scanner_discovery.requests.get", return_value=make_resp(html, status_code=200)):
            result = scanner.test_directory_listing()
        assert result.status == "FAILED"
        assert result.severity == "MEDIUM"


# ─── D-09: Error Disclosure ──────────────────────────────────────────────────

class TestDiscoveryErrorDisclosure:
    def test_passed_no_info_leaked(self, ds):
        scanner, _ = ds
        with patch("scanner_discovery.requests.get",
                   return_value=make_resp("<h1>404 - Page Not Found</h1>", status_code=404)):
            assert scanner.test_error_disclosure().status == "PASSED"

    def test_failed_absolute_path_leaked(self, ds):
        scanner, _ = ds
        with patch("scanner_discovery.requests.get",
                   return_value=make_resp("Fatal error in /var/www/html/app/index.php line 42")):
            result = scanner.test_error_disclosure()
        assert result.status == "FAILED"

    def test_failed_mysql_warning(self, ds):
        scanner, _ = ds
        with patch("scanner_discovery.requests.get",
                   return_value=make_resp("Warning: mysql_fetch_row() expects parameter 1 to be resource")):
            result = scanner.test_error_disclosure()
        assert result.status == "FAILED"


# ─── D-10: Brute Force ───────────────────────────────────────────────────────

class TestDiscoveryBruteForce:
    LOGIN_HTML = (
        "<form action='/login' method='POST'>"
        "<input name='username'><input name='password'>"
        "<p>Login here</p></form>"
    )

    def test_passed_rate_limited_429(self, ds):
        scanner, _ = ds
        with patch("scanner_discovery.requests.get",
                   return_value=make_resp(self.LOGIN_HTML)):
            with patch("scanner_discovery.requests.post",
                       return_value=make_resp("Too Many Requests", status_code=429)):
                assert scanner.test_brute_force_protection().status == "PASSED"

    def test_passed_lockout_message(self, ds):
        scanner, _ = ds
        with patch("scanner_discovery.requests.get",
                   return_value=make_resp(self.LOGIN_HTML)):
            with patch("scanner_discovery.requests.post",
                       return_value=make_resp("Account locked after too many attempts", status_code=200)):
                assert scanner.test_brute_force_protection().status == "PASSED"

    def test_failed_no_rate_limit(self, ds):
        scanner, _ = ds
        with patch("scanner_discovery.requests.get",
                   return_value=make_resp(self.LOGIN_HTML)):
            with patch("scanner_discovery.requests.post",
                       return_value=make_resp("Invalid username or password.", status_code=200)):
                result = scanner.test_brute_force_protection()
        assert result.status == "FAILED"
        assert result.severity == "HIGH"

    def test_error_no_login_page_found(self, ds):
        scanner, _ = ds
        # Trang hoan toan khong co tu khoa nhan dien trang dang nhap
        with patch("scanner_discovery.requests.get",
                   return_value=make_resp("<html><body><h1>About Us</h1><p>Company info</p></body></html>",
                                         status_code=200)):
            result = scanner.test_brute_force_protection()
        assert result.status == "ERROR"
