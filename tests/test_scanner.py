"""
tests/test_scanner.py
Unit tests cho WebSAST_Scanner va DiscoveryScanner.
Toan bo HTTP calls duoc mock, khong can target server that.
"""
import pytest
import requests
from unittest.mock import patch, MagicMock
from websast_framework import WebSAST_Scanner
from scanner_discovery import DiscoveryScanner, FormInfo


BASE = "http://test.local"


# ─── Helpers ─────────────────────────────────────────────────────────────────

def make_response(text="", status_code=200, headers=None):
    """Tạo mock HTTP response."""
    mock = MagicMock()
    mock.text = text
    mock.status_code = status_code
    mock.headers = headers or {}
    return mock


@pytest.fixture
def scanner():
    """Fixture tạo Scanner instance với banner bị tắt."""
    with patch.object(WebSAST_Scanner, '_print_banner'):
        s = WebSAST_Scanner(BASE)
    return s


# ─── V-01: SQL Injection ──────────────────────────────────────────────────────

class TestV01SQLi:
    def test_passed_no_dashboard(self, scanner):
        with patch('websast_framework.requests.Session') as MockSess:
            MockSess.return_value.post.return_value = make_response("Invalid credentials. Please try again.")
            result = scanner.test_v01_sqli_login()
        assert result.vuln_id == "V-01"
        assert result.status == "PASSED"
        assert result.severity == "CRITICAL"

    def test_failed_dashboard_in_response(self, scanner):
        html = "<html><title>Dashboard – EMS</title><body>Dashboard Quản trị</body></html>"
        with patch('websast_framework.requests.Session') as MockSess:
            MockSess.return_value.post.return_value = make_response(html)
            result = scanner.test_v01_sqli_login()
        assert result.status == "FAILED"
        assert "admin' -- " in result.payload
        assert "Dashboard" in result.evidence or "200" in result.evidence

    def test_failed_quan_tri_in_response(self, scanner):
        with patch('websast_framework.requests.Session') as MockSess:
            MockSess.return_value.post.return_value = make_response("Xin chào Admin!")
            result = scanner.test_v01_sqli_login()
        assert result.status == "FAILED"

    def test_connection_error(self, scanner):
        with patch('websast_framework.requests.Session') as MockSess:
            MockSess.return_value.post.side_effect = requests.exceptions.ConnectionError()
            result = scanner.test_v01_sqli_login()
        assert result.status == "ERROR"
        assert "ConnectionError" in result.evidence


# ─── V-07: XSS ───────────────────────────────────────────────────────────────

class TestV07XSS:
    PAYLOAD = "<script>alert('XSS_TEST')</script>"

    def test_passed_payload_encoded(self, scanner):
        with patch.object(scanner.session, 'get', return_value=make_response("Safe &lt;script&gt; output")):
            result = scanner.test_v07_xss_search()
        assert result.status == "PASSED"

    def test_failed_payload_reflected(self, scanner):
        html = f"<div><p>Results for: {self.PAYLOAD}</p></div>"
        with patch.object(scanner.session, 'get', return_value=make_response(html)):
            result = scanner.test_v07_xss_search()
        assert result.status == "FAILED"
        assert result.severity == "HIGH"
        assert self.PAYLOAD in result.evidence

    def test_connection_error(self, scanner):
        with patch.object(scanner.session, 'get', side_effect=requests.exceptions.ConnectionError()):
            result = scanner.test_v07_xss_search()
        assert result.status == "ERROR"


# ─── V-14: Broken Access Control ─────────────────────────────────────────────

class TestV14BrokenAccessControl:
    def test_passed_403(self, scanner):
        with patch.object(scanner.session, 'post', return_value=make_response()):
            with patch.object(scanner.session, 'get', return_value=make_response("Access Denied", 403)):
                result = scanner.test_v14_broken_access_control()
        assert result.status == "PASSED"

    def test_passed_access_denied_text(self, scanner):
        with patch.object(scanner.session, 'post', return_value=make_response()):
            with patch.object(scanner.session, 'get', return_value=make_response("Không có quyền truy cập.", 200)):
                result = scanner.test_v14_broken_access_control()
        assert result.status == "PASSED"

    def test_failed_user_list_visible(self, scanner):
        html = "<html><title>User List</title><body>Danh sách người dùng employee admin</body></html>"
        with patch.object(scanner.session, 'post', return_value=make_response()):
            with patch.object(scanner.session, 'get', return_value=make_response(html)):
                result = scanner.test_v14_broken_access_control()
        assert result.status == "FAILED"
        assert result.severity == "CRITICAL"

    def test_connection_error(self, scanner):
        with patch.object(scanner.session, 'post', return_value=make_response()):
            with patch.object(scanner.session, 'get', side_effect=requests.exceptions.ConnectionError()):
                result = scanner.test_v14_broken_access_control()
        assert result.status == "ERROR"


# ─── V-15: IDOR ──────────────────────────────────────────────────────────────

class TestV15IDOR:
    def test_passed_no_admin_data(self, scanner):
        with patch.object(scanner.session, 'post', return_value=make_response()):
            with patch.object(scanner.session, 'get', return_value=make_response("<p>My Profile — Nguyen Van A</p>")):
                result = scanner.test_v15_idor()
        assert result.status == "PASSED"

    def test_failed_quan_tri_vien(self, scanner):
        html = "<h1>Hồ Sơ: Quản Trị Viên</h1><p>Email: admin@system.com</p>"
        with patch.object(scanner.session, 'post', return_value=make_response()):
            with patch.object(scanner.session, 'get', return_value=make_response(html)):
                result = scanner.test_v15_idor()
        assert result.status == "FAILED"
        assert result.severity == "HIGH"
        assert "Quản Trị Viên" in result.evidence

    def test_failed_administrator_keyword(self, scanner):
        with patch.object(scanner.session, 'post', return_value=make_response()):
            with patch.object(scanner.session, 'get', return_value=make_response("Role: administrator")):
                result = scanner.test_v15_idor()
        assert result.status == "FAILED"

    def test_connection_error(self, scanner):
        with patch.object(scanner.session, 'post', return_value=make_response()):
            with patch.object(scanner.session, 'get', side_effect=requests.exceptions.ConnectionError()):
                result = scanner.test_v15_idor()
        assert result.status == "ERROR"


# ─── V-17: Business Logic ────────────────────────────────────────────────────

class TestV17InputValidation:
    def test_passed_server_rejects(self, scanner):
        with patch.object(scanner.session, 'post', return_value=make_response("Lỗi: Lương phải lớn hơn 0")):
            result = scanner.test_v17_input_validation()
        assert result.status == "PASSED"

    def test_failed_accepts_negative_salary(self, scanner):
        # Login POST returns success, second POST (add employee) also returns success
        responses = [make_response("OK"), make_response("Thêm thành công hacker_logic@test.com")]
        with patch.object(scanner.session, 'post', side_effect=responses):
            result = scanner.test_v17_input_validation()
        assert result.status == "FAILED"
        assert result.severity == "MEDIUM"

    def test_connection_error(self, scanner):
        with patch.object(scanner.session, 'post', side_effect=requests.exceptions.ConnectionError()):
            result = scanner.test_v17_input_validation()
        assert result.status == "ERROR"


# ─── V-19: PHP Version Disclosure ────────────────────────────────────────────

class TestV19PHPDisclosure:
    def test_passed_no_php_info(self, scanner):
        resp = make_response("Normal login page content", headers={"Server": "Apache"})
        with patch('websast_framework.requests.get', return_value=resp):
            result = scanner.test_v19_php_version_disclosure()
        assert result.status == "PASSED"

    def test_failed_php_in_body(self, scanner):
        resp = make_response("Powered by PHP/8.1.20", headers={})
        with patch('websast_framework.requests.get', return_value=resp):
            result = scanner.test_v19_php_version_disclosure()
        assert result.status == "FAILED"
        assert result.severity == "LOW"

    def test_failed_x_powered_by_header(self, scanner):
        resp = make_response("Normal page", headers={"X-Powered-By": "PHP/8.2.0", "Server": "Apache/2.4"})
        with patch('websast_framework.requests.get', return_value=resp):
            result = scanner.test_v19_php_version_disclosure()
        assert result.status == "FAILED"
        assert "X-Powered-By" in result.evidence

    def test_failed_server_header_contains_php(self, scanner):
        resp = make_response("page", headers={"Server": "Apache/2.4 PHP/7.4.33"})
        with patch('websast_framework.requests.get', return_value=resp):
            result = scanner.test_v19_php_version_disclosure()
        assert result.status == "FAILED"

    def test_connection_error(self, scanner):
        with patch('websast_framework.requests.get', side_effect=requests.exceptions.ConnectionError()):
            result = scanner.test_v19_php_version_disclosure()
        assert result.status == "ERROR"


# ─── V-20: Password Hash Disclosure ──────────────────────────────────────────

class TestV20HashDisclosure:
    def test_passed_no_hashes(self, scanner):
        with patch.object(scanner.session, 'post', return_value=make_response()):
            with patch.object(scanner.session, 'get', return_value=make_response("<table><tr><td>Nguyen Van A</td></tr></table>")):
                result = scanner.test_v20_password_hash_disclosure()
        assert result.status == "PASSED"

    def test_failed_md5_hash_found(self, scanner):
        html = "<td>5f4dcc3b5aa765d61d8327deb882cf99</td>"  # MD5 của "password"
        with patch.object(scanner.session, 'post', return_value=make_response()):
            with patch.object(scanner.session, 'get', return_value=make_response(html)):
                result = scanner.test_v20_password_hash_disclosure()
        assert result.status == "FAILED"
        assert result.severity == "HIGH"
        assert "MD5" in result.evidence

    def test_failed_bcrypt_hash_found(self, scanner):
        html = "$2y$10$abc123defghijklmnopqrstu123456789012345678901234567890"
        with patch.object(scanner.session, 'post', return_value=make_response()):
            with patch.object(scanner.session, 'get', return_value=make_response(html)):
                result = scanner.test_v20_password_hash_disclosure()
        assert result.status == "FAILED"
        assert "bcrypt" in result.evidence

    def test_connection_error(self, scanner):
        with patch.object(scanner.session, 'post', return_value=make_response()):
            with patch.object(scanner.session, 'get', side_effect=requests.exceptions.ConnectionError()):
                result = scanner.test_v20_password_hash_disclosure()
        assert result.status == "ERROR"


# ─── V-22: Session Fixation ──────────────────────────────────────────────────

class TestV22SessionFixation:
    def test_passed_session_regenerated(self, scanner):
        """Session ID phải thay đổi sau khi đăng nhập."""
        call_count = {"n": 0}

        def cookies_get(name):
            call_count["n"] += 1
            return "old_session_id" if call_count["n"] == 1 else "new_regenerated_session_id"

        scanner.session.cookies.get = cookies_get
        with patch.object(scanner.session, 'get', return_value=make_response()):
            with patch.object(scanner.session, 'post', return_value=make_response()):
                result = scanner.test_v22_session_fixation()
        assert result.status == "PASSED"
        assert "old_session_id" in result.evidence
        assert "new_regenerated_session_id" in result.evidence

    def test_failed_session_not_changed(self, scanner):
        """Session ID giữ nguyên sau khi đăng nhập → Session Fixation."""
        scanner.session.cookies.get = lambda name: "FIXED_SESSION_12345"
        with patch.object(scanner.session, 'get', return_value=make_response()):
            with patch.object(scanner.session, 'post', return_value=make_response()):
                result = scanner.test_v22_session_fixation()
        assert result.status == "FAILED"
        assert result.severity == "MEDIUM"
        assert "FIXED_SESSION_12345" in result.evidence

    def test_error_no_session_cookie(self, scanner):
        """Không có PHPSESSID nào → ERROR."""
        scanner.session.cookies.get = lambda name: None
        with patch.object(scanner.session, 'get', return_value=make_response()):
            with patch.object(scanner.session, 'post', return_value=make_response()):
                result = scanner.test_v22_session_fixation()
        assert result.status == "ERROR"

    def test_connection_error(self, scanner):
        with patch.object(scanner.session, 'get', side_effect=requests.exceptions.ConnectionError()):
            result = scanner.test_v22_session_fixation()
        assert result.status == "ERROR"
