"""
tests/test_sast_scanner.py
Unit tests cho SASTScanner (V-10, V-12, V-13, V-16, V-21, V-23).
Tất cả hoạt động offline — dùng tmp_path để tạo file PHP giả.
"""
import os
import pytest
from unittest.mock import patch
from sast_scanner import SASTScanner


# ─── Helpers ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sast(tmp_path):
    """Trả về (scanner, tmp_path) với banner bị tắt."""
    with patch.object(SASTScanner, '_print_banner'):
        s = SASTScanner(web_root=str(tmp_path))
    return s, tmp_path


def write_file(base: str, rel_path: str, content: str) -> str:
    """Tạo file và thư mục cha trong tmp_path."""
    full = os.path.join(base, rel_path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(content)
    return full


# ─── V-10: DOM XSS ────────────────────────────────────────────────────────────

class TestV10DomXss:

    def test_passed_no_dangerous_sink(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "assets/js/main.js", "console.log('hello world');")
        result = scanner.test_v10_dom_xss()
        assert result.status == "PASSED"
        assert result.vuln_id == "V-10"

    def test_failed_inner_html_detected(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "assets/js/main.js",
                   "element.innerHTML = userInput;")
        result = scanner.test_v10_dom_xss()
        assert result.status == "FAILED"
        assert "innerHTML" in result.evidence

    def test_failed_document_write_detected(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "assets/js/main.js",
                   "document.write(location.search);")
        result = scanner.test_v10_dom_xss()
        assert result.status == "FAILED"

    def test_failed_eval_detected(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "assets/js/main.js",
                   "eval(userControlledData);")
        result = scanner.test_v10_dom_xss()
        assert result.status == "FAILED"

    def test_error_file_not_found(self, sast):
        scanner, _ = sast
        result = scanner.test_v10_dom_xss(js_relative_path="nonexistent/file.js")
        assert result.status == "ERROR"

    def test_severity_is_high(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "assets/js/main.js", "el.innerHTML = x;")
        result = scanner.test_v10_dom_xss()
        assert result.severity == "HIGH"

    def test_vuln_id_correct(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "assets/js/main.js", "")
        result = scanner.test_v10_dom_xss()
        assert result.vuln_id == "V-10"

    def test_scan_type_is_poc(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "assets/js/main.js", "")
        result = scanner.test_v10_dom_xss()
        assert result.scan_type == "poc"


# ─── V-12: Hardcoded DB Password ──────────────────────────────────────────────

class TestV12HardcodedDbPassword:

    def test_failed_password_variable_found(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "config/db.php",
                   "<?php $db_password = 'secret123'; ?>")
        result = scanner.test_v12_hardcoded_db_password()
        assert result.status == "FAILED"
        assert "secret123" in result.evidence or "db_password" in result.evidence

    def test_failed_define_constant_found(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "config/db.php",
                   "<?php define('DB_PASS', 'my_db_pass'); ?>")
        result = scanner.test_v12_hardcoded_db_password()
        assert result.status == "FAILED"

    def test_passed_empty_password(self, sast):
        scanner, tmp = sast
        # Mật khẩu trống không tính là hardcoded
        write_file(str(tmp), "config/db.php",
                   "<?php $host = 'localhost'; $dbname = 'cms'; ?>")
        result = scanner.test_v12_hardcoded_db_password()
        assert result.status == "PASSED"

    def test_error_file_not_found(self, sast):
        scanner, _ = sast
        result = scanner.test_v12_hardcoded_db_password(config_relative_path="not/exist.php")
        assert result.status == "ERROR"

    def test_severity_critical(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "config/db.php", "<?php $db_pass = 'abc123'; ?>")
        result = scanner.test_v12_hardcoded_db_password()
        assert result.severity == "CRITICAL"


# ─── V-13: Hardcoded App Secret ────────────────────────────────────────────────

class TestV13HardcodedAppSecret:

    def test_failed_secret_key_variable(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "config/db.php",
                   "<?php $secret_key = 'super_secret_value'; ?>")
        result = scanner.test_v13_hardcoded_app_secret()
        assert result.status == "FAILED"

    def test_failed_define_jwt_secret(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "config/db.php",
                   "<?php define('JWT_SECRET', 'my_jwt_value_here'); ?>")
        result = scanner.test_v13_hardcoded_app_secret()
        assert result.status == "FAILED"

    def test_passed_no_secret(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "config/db.php",
                   "<?php $host = 'localhost'; ?>")
        result = scanner.test_v13_hardcoded_app_secret()
        assert result.status == "PASSED"

    def test_error_file_not_found(self, sast):
        scanner, _ = sast
        result = scanner.test_v13_hardcoded_app_secret(config_relative_path="no/file.php")
        assert result.status == "ERROR"

    def test_severity_critical(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "config/db.php", "<?php $api_key = 'abcdefghij'; ?>")
        result = scanner.test_v13_hardcoded_app_secret()
        assert result.severity == "CRITICAL"


# ─── V-16: No CSRF Protection ──────────────────────────────────────────────────

class TestV16NoCsrfProtection:

    def test_failed_post_form_missing_token(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "employees/add.php",
                   '<form method="post"><input name="salary"><button>Submit</button></form>')
        result = scanner.test_v16_no_csrf_protection(scan_dirs=["employees"])
        assert result.status == "FAILED"
        assert "add.php" in result.evidence

    def test_passed_form_has_csrf_token(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "employees/edit.php",
                   '<form method="POST">'
                   '<input type="hidden" name="csrf_token" value="abc">'
                   '<input name="name"></form>')
        result = scanner.test_v16_no_csrf_protection(scan_dirs=["employees"])
        assert result.status == "PASSED"

    def test_passed_form_has_underscore_token(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "auth/login.php",
                   '<form method="post">'
                   '<input type="hidden" name="_token" value="xyz">'
                   '<input name="password"></form>')
        result = scanner.test_v16_no_csrf_protection(scan_dirs=["auth"])
        assert result.status == "PASSED"

    def test_error_no_php_files(self, sast):
        scanner, _ = sast
        result = scanner.test_v16_no_csrf_protection(scan_dirs=["nonexistent_dir"])
        assert result.status == "ERROR"

    def test_severity_high(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "admin/delete.php",
                   '<form method="post"><input name="id"></form>')
        result = scanner.test_v16_no_csrf_protection(scan_dirs=["admin"])
        assert result.severity == "HIGH"

    def test_mixed_forms_counts_correct(self, sast):
        """Có cả form an toàn và form thiếu token — chỉ báo FAILED với form thiếu."""
        scanner, tmp = sast
        write_file(str(tmp), "employees/add.php",
                   '<form method="post"><input name="salary"></form>')
        write_file(str(tmp), "employees/edit.php",
                   '<form method="POST"><input type="hidden" name="csrf_token" value="x">'
                   '<input name="name"></form>')
        result = scanner.test_v16_no_csrf_protection(scan_dirs=["employees"])
        assert result.status == "FAILED"
        assert "1/2" in result.description or "1/" in result.description


# ─── V-21: Weak MD5 Hashing ────────────────────────────────────────────────────

class TestV21WeakMd5Hashing:

    def test_failed_md5_password_context(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "auth/login.php",
                   "<?php\n"
                   "$password = $_POST['password'];\n"
                   "$hash = md5($password);\n"
                   "?>")
        result = scanner.test_v21_weak_md5_hashing(scan_dirs=["auth"])
        assert result.status == "FAILED"
        assert "md5" in result.evidence.lower()

    def test_failed_sha1_password_context(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "auth/register.php",
                   "<?php\n"
                   "$pass = sha1($password);\n"
                   "?>")
        result = scanner.test_v21_weak_md5_hashing(scan_dirs=["auth"])
        assert result.status == "FAILED"

    def test_passed_md5_non_password_context(self, sast):
        """md5() dùng cho checksum file — không có từ password/pass/pwd trong file."""
        scanner, tmp = sast
        write_file(str(tmp), "includes/utils.php",
                   "<?php\n"
                   "function compute_etag($filepath) {\n"
                   "    $content = file_get_contents($filepath);\n"
                   "    return md5($content);\n"
                   "}\n"
                   "?>"
                   )
        result = scanner.test_v21_weak_md5_hashing(scan_dirs=["includes"])
        assert result.status == "PASSED"

    def test_passed_no_php_files(self, sast):
        scanner, _ = sast
        result = scanner.test_v21_weak_md5_hashing(scan_dirs=["no_exist"])
        assert result.status == "PASSED"

    def test_severity_high(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "auth/hash.php",
                   "<?php $h = md5($password); ?>")
        result = scanner.test_v21_weak_md5_hashing(scan_dirs=["auth"])
        assert result.severity == "HIGH"


# ─── V-23: Password in Session ─────────────────────────────────────────────────

class TestV23PasswordInSession:

    def test_failed_session_password_stored(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "auth/login.php",
                   "<?php\n"
                   "$_SESSION['username'] = $username;\n"
                   "$_SESSION['password'] = $password;\n"
                   "?>")
        result = scanner.test_v23_password_in_session()
        assert result.status == "FAILED"
        assert "password" in result.evidence.lower()

    def test_failed_session_pass_stored(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "auth/login.php",
                   "<?php $_SESSION['user_pass'] = md5($pwd); ?>")
        result = scanner.test_v23_password_in_session()
        assert result.status == "FAILED"

    def test_passed_only_safe_session_vars(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "auth/login.php",
                   "<?php\n"
                   "$_SESSION['user_id'] = $user['id'];\n"
                   "$_SESSION['role'] = $user['role'];\n"
                   "$_SESSION['username'] = $user['name'];\n"
                   "?>")
        result = scanner.test_v23_password_in_session()
        assert result.status == "PASSED"

    def test_error_file_not_found(self, sast):
        scanner, _ = sast
        result = scanner.test_v23_password_in_session(auth_relative_path="not/found.php")
        assert result.status == "ERROR"

    def test_severity_high(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "auth/login.php",
                   "<?php $_SESSION['password'] = $pass; ?>")
        result = scanner.test_v23_password_in_session()
        assert result.severity == "HIGH"

    def test_scan_type_is_poc(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "auth/login.php", "<?php ?>")
        result = scanner.test_v23_password_in_session()
        assert result.scan_type == "poc"


# ─── SASTScanner.run_all_sast_tests ────────────────────────────────────────────

class TestSASTScannerRunAll:

    def test_run_returns_6_results(self, sast):
        scanner, tmp = sast
        # Tạo đủ file để tránh ERROR
        write_file(str(tmp), "assets/js/main.js", "console.log(1);")
        write_file(str(tmp), "config/db.php", "<?php $host='localhost'; ?>")
        write_file(str(tmp), "auth/login.php", "<?php $_SESSION['id'] = 1; ?>")
        results = scanner.run_all_sast_tests()
        assert len(results) == 6

    def test_run_returns_scan_result_objects(self, sast):
        from report_generator import ScanResult
        scanner, tmp = sast
        write_file(str(tmp), "assets/js/main.js", "")
        write_file(str(tmp), "config/db.php", "<?php ?>")
        write_file(str(tmp), "auth/login.php", "<?php ?>")
        results = scanner.run_all_sast_tests()
        for r in results:
            assert isinstance(r, ScanResult)

    def test_run_vuln_ids_correct(self, sast):
        scanner, tmp = sast
        write_file(str(tmp), "assets/js/main.js", "")
        write_file(str(tmp), "config/db.php", "<?php ?>")
        write_file(str(tmp), "auth/login.php", "<?php ?>")
        results = scanner.run_all_sast_tests()
        ids = [r.vuln_id for r in results]
        assert "V-10" in ids
        assert "V-12" in ids
        assert "V-13" in ids
        assert "V-16" in ids
        assert "V-21" in ids
        assert "V-23" in ids
