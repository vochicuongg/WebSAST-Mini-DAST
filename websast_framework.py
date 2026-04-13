"""
websast_framework.py
WebSAST Automated Exploitation Framework — DAST Engine
Quét 23 lỗ hổng: DAST (HTTP requests) + tích hợp SAST + Generic Discovery.
"""

import argparse
import re
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from datetime import datetime
from report_generator import HtmlReportGenerator, ScanResult
from scanner_discovery import DiscoveryScanner
from sast_scanner import SASTScanner

# Khởi tạo màu sắc cho Terminal
init(autoreset=True)

EVIDENCE_MAX_LEN = 500


def _truncate(text: str, limit: int = EVIDENCE_MAX_LEN) -> str:
    """Cắt ngắn chuỗi nếu vượt quá giới hạn."""
    text = str(text).strip()
    if len(text) > limit:
        return text[:limit] + f"\n... [Đã cắt ngắn, tổng {len(text)} ký tự]"
    return text


def _extract_text_snippet(html: str, keyword: str = None, max_len: int = EVIDENCE_MAX_LEN) -> str:
    """Trích xuất đoạn text có nghĩa từ HTML, ưu tiên đoạn chứa keyword."""
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style"]):
            tag.decompose()
        text = soup.get_text(separator=" ", strip=True)
        if keyword:
            idx = text.lower().find(keyword.lower())
            if idx != -1:
                start = max(0, idx - 100)
                return _truncate(text[start:], max_len)
        return _truncate(text, max_len)
    except Exception:
        return _truncate(html, max_len)


# ─────────────────────────────────────────────────────────────────────────────
class WebSAST_Scanner:
    """DAST Scanner: kiểm thử bằng HTTP request thực tế lên web server."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.max_redirects = 5  # Giảm số lần redirect tối đa trước khi báo lỗi
        self._print_banner()

    def _print_banner(self):
        print(Fore.CYAN + "=" * 70)
        print(Fore.CYAN + "  🛡️  WebSAST AUTOMATED EXPLOITATION FRAMEWORK v2.0")
        print(Fore.CYAN + "=" * 70 + "\n")

    def _now(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _print_result(self, result: ScanResult):
        if result.status == "FAILED":
            color, icon = Fore.RED, "=> [FAILED]"
        elif result.status == "PASSED":
            color, icon = Fore.GREEN, "=> [PASSED]"
        else:
            color, icon = Fore.YELLOW, "=> [ERROR/SKIP]"

        print(Fore.YELLOW + f"[*] Đang test {result.vuln_id}: {result.name}...")
        print(color + f"    {icon} {result.description}")
        if result.status == "FAILED" and result.evidence and result.evidence != "N/A":
            print(Fore.WHITE + Style.DIM
                  + f"    📌 Evidence: {result.evidence[:200]}{'...' if len(result.evidence) > 200 else ''}")
        if result.payload and result.payload != "N/A":
            print(Fore.WHITE + Style.DIM + f"    💉 Payload: {result.payload}")
        print("-" * 60)

    def login(self, username: str, password: str) -> bool:
        """Đăng nhập và duy trì session."""
        login_url = f"{self.base_url}/auth/login.php"
        try:
            resp = self.session.post(login_url, data={"username": username, "password": password}, timeout=10)
            return resp.status_code == 200 and ("Dashboard" in resp.text or "Xin chào" in resp.text
                                                or "logout" in resp.text.lower())
        except Exception:
            return False

    # ─────────────────────────────────────────────────────────────
    # HÀM DÙNG CHUNG: SQL Injection Generic (DRY)
    # ─────────────────────────────────────────────────────────────
    def _test_sqli_generic(
        self,
        vuln_id: str,
        name: str,
        url: str,
        method: str,           # "GET" hoặc "POST"
        param_name: str,       # tên tham số bị tấn công
        extra_data: dict,      # tham số bổ sung cần gửi kèm
        severity: str = "CRITICAL",
        need_login: tuple | None = None,   # ("user","pass") nếu cần auth trước
    ) -> ScanResult:
        """
        Template chung cho mọi test SQLi.
        Thử tuần tự 3 payload, báo FAILED ngay khi tìm thấy dấu hiệu.
        """
        if need_login:
            self.login(*need_login)

        sqli_payloads = [
            ("'", "Quote đơn gây lỗi cú pháp SQL"),
            ("1' OR '1'='1' -- ", "OR bypass authentication"),
            ("' UNION SELECT NULL,NULL,NULL -- ", "UNION-based detection"),
        ]
        sqli_errors = [
            "sql syntax", "mysql_fetch", "warning: mysqli", "sqlstate",
            "ora-", "unclosed quotation", "you have an error in your sql",
            "supplied argument is not a valid mysql", "pg_query",
        ]

        status, evidence, hit_payload = "PASSED", "N/A", None
        description = f"An toàn. Không phát hiện lỗ hổng SQL Injection tại tham số '{param_name}'."

        try:
            for payload, label in sqli_payloads:
                data = {**extra_data, param_name: payload}
                resp = (
                    self.session.post(url, data=data, timeout=10, allow_redirects=False)
                    if method.upper() == "POST"
                    else self.session.get(url, params=data, timeout=10, allow_redirects=False)
                )
                body_lower = resp.text.lower()
                for err in sqli_errors:
                    if err in body_lower:
                        status = "FAILED"
                        hit_payload = payload
                        idx = body_lower.find(err)
                        snippet = resp.text[max(0, idx - 80): idx + 200]
                        evidence = (
                            f"Payload: {payload!r} ({label})\n"
                            f"HTTP Status: {resp.status_code}\n"
                            f"Error keyword '{err}' tại offset {idx}:\n"
                            + _truncate(snippet)
                        )
                        description = (
                            f"Lỗ hổng SQL Injection TỒN TẠI! Tham số '{param_name}' "
                            f"phản hồi lỗi SQL với payload {payload!r}."
                        )
                        break
                if status == "FAILED":
                    break

        except requests.exceptions.ConnectionError:
            status, description = "ERROR", "Không thể kết nối tới URL mục tiêu."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status, description = "ERROR", f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id=vuln_id, name=name,
            severity=severity, status=status, description=description,
            payload=hit_payload or sqli_payloads[0][0],
            evidence=evidence, url=url,
            recommendation=(
                "Sử dụng Prepared Statements (PDO/MySQLi bindParam) cho MỌI câu query. "
                "Không bao giờ nối chuỗi user input trực tiếp vào SQL. "
                "Bật chế độ strict_types và validate kiểu dữ liệu đầu vào."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    # ─────────────────────────────────────────────────────────────
    # HÀM DÙNG CHUNG: XSS Reflected Generic (DRY)
    # ─────────────────────────────────────────────────────────────
    def _test_xss_reflected_generic(
        self,
        vuln_id: str,
        name: str,
        url: str,
        method: str,
        param_name: str,
        extra_data: dict,
        severity: str = "HIGH",
        need_login: tuple | None = None,
    ) -> ScanResult:
        """Template chung cho mọi test XSS Reflected."""
        if need_login:
            self.login(*need_login)

        payload = "<script>alert('XSS_DAST')</script>"
        status, evidence = "PASSED", "N/A"
        description = f"An toàn. Dữ liệu đầu vào tại tham số '{param_name}' đã được encode/lọc."

        try:
            data = {**extra_data, param_name: payload}
            resp = (
                self.session.post(url, data=data, timeout=10, allow_redirects=False)
                if method.upper() == "POST"
                else self.session.get(url, params=data, timeout=10, allow_redirects=False)
            )

            if payload in resp.text:
                status = "FAILED"
                idx = resp.text.find(payload)
                snippet = resp.text[max(0, idx - 80): idx + len(payload) + 80]
                description = (
                    f"Lỗ hổng XSS Reflected TỒN TẠI! Payload phản chiếu thẳng ra HTML "
                    f"tại tham số '{param_name}' mà không qua encoding."
                )
                evidence = (
                    f"Payload phát hiện tại offset {idx}:\n"
                    + _truncate(snippet)
                )

        except requests.exceptions.ConnectionError:
            status, description = "ERROR", "Không thể kết nối tới URL mục tiêu."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status, description = "ERROR", f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id=vuln_id, name=name,
            severity=severity, status=status, description=description,
            payload=payload, evidence=evidence, url=url,
            recommendation=(
                "Áp dụng htmlspecialchars($val, ENT_QUOTES, 'UTF-8') cho mọi giá trị output. "
                "Triển khai Content-Security-Policy (CSP) header để hạn chế thực thi script ngoài ý muốn."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    # =========================================================
    # MODULE 1: SQL INJECTION (V-01 → V-06)
    # =========================================================

    def test_v01_sqli_login(self) -> ScanResult:
        """[DAST] SQLi Auth Bypass qua form đăng nhập."""
        url = f"{self.base_url}/auth/login.php"
        payload = "admin' -- "
        evidence, status = "N/A", "PASSED"
        description = "An toàn. Không bị SQLi Bypass tại form Đăng nhập."

        try:
            temp_session = requests.Session()
            resp = temp_session.post(url, data={"username": payload, "password": "123"}, timeout=10)
            if "Dashboard" in resp.text or "Quản trị" in resp.text or "Xin chào" in resp.text:
                status = "FAILED"
                description = f"Lỗ hổng SQLi Bypass TỒN TẠI! Mật khẩu bị vô hiệu hóa bởi payload: {payload!r}"
                soup = BeautifulSoup(resp.text, "html.parser")
                title = soup.find("title")
                evidence = (f"Trạng thái HTTP: {resp.status_code} | "
                            f"Title trang sau bypass: {title.text.strip() if title else 'N/A'}\n"
                            + _extract_text_snippet(resp.text, keyword="Dashboard"))
        except requests.exceptions.ConnectionError:
            status, description = "ERROR", "Không thể kết nối tới URL mục tiêu."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status, description = "ERROR", f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-01", name="SQL Injection (Login Auth Bypass)",
            severity="CRITICAL", status=status, description=description,
            payload=payload, evidence=evidence, url=url,
            recommendation=(
                "Sử dụng Prepared Statements (PDO/MySQLi) cho toàn bộ câu query. "
                "Không nối chuỗi trực tiếp giá trị người dùng vào SQL."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    def test_v02_to_v06_sqli_batch(self) -> list[ScanResult]:
        """[DAST] Nhóm 5 lỗi SQLi (V-02 đến V-06) thành 1 hàm truyền tham số (DRY)."""
        self.login("admin", "admin123")
        cases = [
            ("V-02", "SQL Injection (Search — employees/search.php)", f"{self.base_url}/employees/search.php", "GET", "search", {}),
            ("V-03", "SQL Injection (Edit Employee — employees/edit.php)", f"{self.base_url}/employees/edit.php", "POST", "id", {"fullname": "Test", "email": "t@t.com", "salary": "1000", "status": "1"}),
            ("V-04", "SQL Injection (Delete Employee — employees/delete.php)", f"{self.base_url}/employees/delete.php", "GET", "id", {}),
            ("V-05", "SQL Injection (View Employee — employees/view.php)", f"{self.base_url}/employees/view.php", "GET", "id", {}),
            ("V-06", "SQL Injection (List Filter — employees/list.php)", f"{self.base_url}/employees/list.php", "GET", "department", {"status": "1"}),
        ]
        
        results = []
        for vuln_id, name, url, method, param_name, extra_data in cases:
            res = self._test_sqli_generic(
                vuln_id=vuln_id,
                name=name,
                url=url,
                method=method,
                param_name=param_name,
                extra_data=extra_data
            )
            results.append(res)
        return results

    # =========================================================
    # MODULE 2: XSS (V-07 → V-09, V-11)
    # =========================================================

    def test_v07_xss_search(self) -> ScanResult:
        """[DAST] XSS Reflected tại form tìm kiếm nhân viên."""
        return self._test_xss_reflected_generic(
            vuln_id="V-07", name="XSS Reflected (Search — employees/search.php)",
            url=f"{self.base_url}/employees/search.php",
            method="GET", param_name="search", extra_data={},
            need_login=("admin", "admin123"),
        )

    def test_v08_xss_stored_notes(self) -> ScanResult:
        """[DAST] XSS Stored: tiêm payload vào trường ghi chú, sau đó load lại trang để xem có phản chiếu không."""
        self.login("admin", "admin123")
        xss_payload = "<img src=x onerror=\"alert('XSS_STORED_V8')\">"
        post_url = f"{self.base_url}/employees/view.php"
        status, evidence = "PASSED", "N/A"
        description = "An toàn. Payload XSS Stored đã được encode trước khi lưu hoặc hiển thị."
        employee_id = "1"

        try:
            # Gửi payload vào trường note
            self.session.post(
                post_url,
                data={"id": employee_id, "note": xss_payload, "action": "add_note"},
                timeout=10, allow_redirects=False
            )
            # Load lại trang để kiểm tra payload có hiển thị không
            resp = self.session.get(post_url, params={"id": employee_id}, timeout=10, allow_redirects=False)
            if xss_payload in resp.text:
                status = "FAILED"
                idx = resp.text.find(xss_payload)
                snippet = resp.text[max(0, idx - 60): idx + len(xss_payload) + 80]
                description = "Lỗ hổng XSS Stored TỒN TẠI! Payload được lưu vào DB và phản chiếu lại mà không qua encoding."
                evidence = f"Payload '...onerror=alert...' tìm thấy tại offset {idx}:\n" + _truncate(snippet)
        except requests.exceptions.ConnectionError:
            status, description = "ERROR", "Không thể kết nối tới URL mục tiêu."
            evidence = f"ConnectionError: {post_url}"
        except Exception as e:
            status, description = "ERROR", f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-08", name="XSS Stored (Notes — employees/view.php)",
            severity="CRITICAL", status=status, description=description,
            payload=xss_payload, evidence=evidence, url=post_url,
            recommendation=(
                "Áp dụng htmlspecialchars() khi hiển thị dữ liệu từ database. "
                "Lọc/strip các thẻ HTML nguy hiểm trước khi lưu vào DB bằng strip_tags() hoặc thư viện HTML Purifier."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    def test_v09_xss_reflected_login(self) -> ScanResult:
        """[DAST] XSS Reflected tại tham số username của form login (thông báo lỗi phản chiếu)."""
        return self._test_xss_reflected_generic(
            vuln_id="V-09", name="XSS Reflected (Login Error — auth/login.php)",
            url=f"{self.base_url}/auth/login.php",
            method="POST", param_name="username",
            extra_data={"password": "wrong_pass"},
        )

    def test_v11_xss_url_params(self) -> ScanResult:
        """[DAST] XSS qua tham số URL được phản chiếu trong header/breadcrumb."""
        return self._test_xss_reflected_generic(
            vuln_id="V-11", name="XSS in URL Params (includes/header.php)",
            url=f"{self.base_url}/includes/header.php",
            method="GET", param_name="page",
            extra_data={},
            need_login=("admin", "admin123"),
        )

    # =========================================================
    # MODULE 3: ACCESS CONTROL & IDOR (V-14, V-15)
    # =========================================================

    def test_v14_broken_access_control(self) -> ScanResult:
        """[DAST] User thường (role=user) truy cập trang admin."""
        self.login("user", "user123")
        url = f"{self.base_url}/admin/users.php"
        status, evidence = "PASSED", "N/A"
        description = "An toàn. Hệ thống đã chặn truy cập trái phép tới trang Admin."

        try:
            resp = self.session.get(url, timeout=10, allow_redirects=False)
            if "Danh sách người dùng" in resp.text or "employee" in resp.text.lower():
                status = "FAILED"
                description = (f"Lỗ hổng Broken Access Control TỒN TẠI! "
                               f"User thường truy cập được trang Admin (HTTP {resp.status_code}).")
                soup = BeautifulSoup(resp.text, "html.parser")
                title = soup.find("title")
                evidence = (f"HTTP Status: {resp.status_code} | Title: {title.text.strip() if title else 'N/A'}\n"
                            + _extract_text_snippet(resp.text, keyword="người dùng"))
            elif resp.status_code in (403, 401):
                description = f"An toàn. Server trả về HTTP {resp.status_code} — Truy cập bị từ chối đúng cách."
                evidence = f"HTTP Status: {resp.status_code}"
            elif "Không có quyền" in resp.text or "Access Denied" in resp.text:
                description = "An toàn. Server hiển thị thông báo từ chối truy cập."
                evidence = _extract_text_snippet(resp.text, keyword="quyền")

        except requests.exceptions.ConnectionError:
            status, description = "ERROR", "Không thể kết nối."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status, description = "ERROR", f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-14", name="Broken Access Control (Privilege Escalation)",
            severity="CRITICAL", status=status, description=description,
            payload="Đăng nhập: user/user123 → Truy cập trực tiếp /admin/users.php",
            evidence=evidence, url=url,
            recommendation=(
                "Kiểm tra phân quyền (RBAC) ở phía server cho MỌI route. "
                "Không chỉ kiểm tra ở frontend/JavaScript."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    def test_v15_idor(self) -> ScanResult:
        """[DAST] User thường đọc profile của Admin qua tham số id=1."""
        self.login("user", "user123")
        url = f"{self.base_url}/user/profile.php?id=1"
        status, evidence = "PASSED", "N/A"
        description = "An toàn. Không thể xem hồ sơ của người dùng khác (IDOR được chặn)."

        try:
            resp = self.session.get(url, timeout=10, allow_redirects=False)
            indicators = ["Quản Trị Viên", "administrator", "admin@"]
            found = [kw for kw in indicators if kw.lower() in resp.text.lower()]
            if found:
                status = "FAILED"
                description = (f"Lỗ hổng IDOR TỒN TẠI! User thường đọc được dữ liệu của ID=1 (Admin). "
                               f"Dấu hiệu: {', '.join(found)}")
                evidence = (f"HTTP Status: {resp.status_code} | Từ khoá: {', '.join(found)}\n"
                            + _extract_text_snippet(resp.text, keyword=found[0]))
        except requests.exceptions.ConnectionError:
            status, description = "ERROR", "Không thể kết nối."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status, description = "ERROR", f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-15", name="IDOR — Insecure Direct Object Reference (Profile)",
            severity="HIGH", status=status, description=description,
            payload="GET /user/profile.php?id=1 (thay đổi tham số id)",
            evidence=evidence, url=url,
            recommendation=(
                "Validate server-side rằng user hiện tại chỉ được truy cập tài nguyên của chính mình. "
                "Dùng session UserID thay vì tin vào tham số URL."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    # =========================================================
    # MODULE 4: INPUT VALIDATION & LOGIC (V-17, V-18)
    # =========================================================

    def test_v17_input_validation(self) -> ScanResult:
        """[DAST] Gửi mức lương âm — kiểm tra backend có từ chối không."""
        self.login("admin", "admin123")
        url = f"{self.base_url}/employees/add.php"
        payload_data = {
            "fullname": "DAST Logic Test",
            "email": "dast_negative_salary@test.com",
            "salary": "-9999999",
            "status": "1",
        }
        status, evidence = "PASSED", "N/A"
        description = "An toàn. Dữ liệu bất hợp lý (lương âm) đã bị từ chối bởi server."

        try:
            resp = self.session.post(url, data=payload_data, timeout=10, allow_redirects=False)
            success_keywords = ["thành công", "successfully", "dast_negative_salary@test.com"]
            found = [kw for kw in success_keywords if kw.lower() in resp.text.lower()]
            if found:
                status = "FAILED"
                description = "Lỗ hổng Business Logic TỒN TẠI! Backend chấp nhận lưu mức lương ÂM vào hệ thống."
                evidence = (f"HTTP Status: {resp.status_code} | Từ khoá thành công: {', '.join(found)}\n"
                            + _extract_text_snippet(resp.text, keyword=found[0]))
        except requests.exceptions.ConnectionError:
            status, description = "ERROR", "Không thể kết nối."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status, description = "ERROR", f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-17", name="Business Logic Flaw — No Input Validation (Lương Âm)",
            severity="MEDIUM", status=status, description=description,
            payload=str(payload_data), evidence=evidence, url=url,
            recommendation=(
                "Validate tại Backend: salary > 0, email hợp lệ, và mọi ràng buộc nghiệp vụ. "
                "Không chỉ validate ở client-side JavaScript."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    def test_v18_sql_error_disclosure(self) -> ScanResult:
        """[DAST] Kích hoạt lỗi SQL và kiểm tra server có lộ thông tin lỗi chi tiết không."""
        self.login("admin", "admin123")
        target_urls = [
            f"{self.base_url}/employees/search.php?search='",
            f"{self.base_url}/employees/view.php?id='",
            f"{self.base_url}/employees/list.php?department='",
        ]
        sql_error_patterns = [
            "you have an error in your sql", "warning: mysqli",
            "mysql_fetch", "sqlstate", "sql syntax",
        ]
        disclosure_found = []
        status, evidence = "PASSED", "N/A"
        description = "An toàn. Server không lộ thông tin lỗi SQL chi tiết ra giao diện."

        try:
            for url in target_urls:
                resp = self.session.get(url, timeout=10, allow_redirects=False)
                for pattern in sql_error_patterns:
                    if pattern in resp.text.lower():
                        idx = resp.text.lower().find(pattern)
                        snippet = resp.text[max(0, idx - 40): idx + 200]
                        disclosure_found.append(
                            f"URL: {url}\nKeyword: '{pattern}'\nSnippet: {snippet[:150]}"
                        )
                        break

            if disclosure_found:
                status = "FAILED"
                description = (f"Lỗ hổng SQL Error Disclosure TỒN TẠI! "
                               f"Server lộ {len(disclosure_found)} thông báo lỗi SQL chi tiết.")
                evidence = _truncate("\n---\n".join(disclosure_found[:3]))

        except requests.exceptions.ConnectionError:
            status, description = "ERROR", "Không thể kết nối."
            evidence = "ConnectionError"
        except Exception as e:
            status, description = "ERROR", f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-18", name="SQL Error Message Disclosure",
            severity="MEDIUM", status=status, description=description,
            payload="GET /search.php?search=' | /view.php?id=' (kích hoạt lỗi SQL)",
            evidence=evidence, url=f"{self.base_url}/employees/",
            recommendation=(
                "Đặt display_errors = Off trong php.ini. "
                "Dùng try-catch để bắt lỗi DB và hiển thị thông báo chung chung cho user. "
                "Ghi error log ra file thay vì màn hình."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    # =========================================================
    # MODULE 5: INFORMATION DISCLOSURE & SESSION (V-19 → V-22)
    # =========================================================

    def test_v19_php_version_disclosure(self) -> ScanResult:
        """[DAST] Kiểm tra PHP version bị lộ qua body hoặc headers."""
        url = f"{self.base_url}/auth/login.php"
        status, evidence = "PASSED", "N/A"
        description = "An toàn. Phiên bản PHP không bị lộ trong phản hồi."

        try:
            resp = requests.get(url, timeout=10, allow_redirects=False)
            body_match = re.search(r'PHP[/\s]([5-9]\.\d+\.\d+)', resp.text)
            server_header = resp.headers.get("Server", "")
            powered_by = resp.headers.get("X-Powered-By", "")

            leaks = []
            if body_match:
                leaks.append(f"Body: {body_match.group(0)}")
            if "php" in server_header.lower():
                leaks.append(f"Server Header: {server_header}")
            if "php" in powered_by.lower():
                leaks.append(f"X-Powered-By Header: {powered_by}")

            if leaks:
                status = "FAILED"
                description = f"Lỗ hổng PHP Version Disclosure TỒN TẠI! Phiên bản PHP bị lộ: {'; '.join(leaks)}"
                evidence = (f"HTTP Status: {resp.status_code}\n"
                            f"Server: {server_header or 'N/A'}\n"
                            f"X-Powered-By: {powered_by or 'N/A'}")
                if body_match:
                    idx = resp.text.find(body_match.group(0))
                    evidence += f"\nTrong body tại offset {idx}: ...{resp.text[max(0, idx-50):idx+100]}..."

        except requests.exceptions.ConnectionError:
            status, description = "ERROR", "Không thể kết nối."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status, description = "ERROR", f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-19", name="PHP Version Disclosure (Headers & Body)",
            severity="LOW", status=status, description=description,
            payload="HTTP GET — Quan sát response headers và body",
            evidence=evidence, url=url,
            recommendation=(
                "Đặt 'expose_php = Off' trong php.ini. "
                "Cấu hình Apache/Nginx để ẩn header Server."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    def test_v20_password_hash_disclosure(self) -> ScanResult:
        """[DAST] Admin xem trang users.php — kiểm tra hash mật khẩu có bị in ra UI không."""
        self.login("admin", "admin123")
        url = f"{self.base_url}/admin/users.php"
        status, evidence = "PASSED", "N/A"
        description = "An toàn. Mật khẩu đã mã hóa không bị in ra giao diện người dùng."

        try:
            resp = self.session.get(url, timeout=10, allow_redirects=False)
            md5_hashes = re.findall(r'\b[a-fA-F0-9]{32}\b', resp.text)
            bcrypt_hashes = re.findall(r'\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}', resp.text)
            sha1_hashes = re.findall(r'\b[a-fA-F0-9]{40}\b', resp.text)

            all_found = []
            if md5_hashes:
                all_found.append(f"MD5 ({len(md5_hashes)} chuỗi): {', '.join(md5_hashes[:3])}")
            if bcrypt_hashes:
                all_found.append(f"bcrypt ({len(bcrypt_hashes)} chuỗi)")
            if sha1_hashes:
                all_found.append(f"SHA1 ({len(sha1_hashes)} chuỗi): {', '.join(sha1_hashes[:3])}")

            if all_found:
                status = "FAILED"
                description = f"Lỗ hổng Hash Disclosure TỒN TẠI! Hash mật khẩu lộ ra UI: {'; '.join(all_found)}"
                evidence = f"HTTP Status: {resp.status_code}\n" + "\n".join(all_found)

        except requests.exceptions.ConnectionError:
            status, description = "ERROR", "Không thể kết nối."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status, description = "ERROR", f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-20", name="Password Hash Disclosure (UI — MD5/bcrypt/SHA1)",
            severity="HIGH", status=status, description=description,
            payload="Đăng nhập admin → GET /admin/users.php",
            evidence=evidence, url=url,
            recommendation=(
                "Không bao giờ hiển thị hash mật khẩu trên giao diện. "
                "Dùng bcrypt/Argon2 thay vì MD5/SHA1."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    def test_v22_session_fixation(self) -> ScanResult:
        """[DAST] Kiểm tra PHPSESSID có được làm mới sau khi đăng nhập không."""
        url = f"{self.base_url}/auth/login.php"
        status, evidence = "PASSED", "N/A"
        description = "An toàn. Session ID được làm mới sau khi đăng nhập thành công."

        try:
            self.session.get(url, timeout=10, allow_redirects=False)
            id_before = self.session.cookies.get("PHPSESSID")
            self.login("user", "user123")
            id_after = self.session.cookies.get("PHPSESSID")
            evidence = (f"Session ID trước đăng nhập: {id_before or 'Không có'}\n"
                        f"Session ID sau đăng nhập:  {id_after or 'Không có'}")

            if id_before is not None and id_before == id_after:
                status = "FAILED"
                description = (f"Lỗ hổng Session Fixation TỒN TẠI! "
                               f"Session ID không được làm mới sau khi đăng nhập (PHPSESSID: {id_after}).")
            elif id_before is None and id_after is None:
                status = "ERROR"
                description = "Không tìm thấy cookie PHPSESSID. Có thể server không dùng PHP session."

        except requests.exceptions.ConnectionError:
            status, description = "ERROR", "Không thể kết nối."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status, description = "ERROR", f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-22", name="Session Fixation (PHPSESSID Regeneration)",
            severity="MEDIUM", status=status, description=description,
            payload="GET /auth/login.php → ghi nhận PHPSESSID → POST login → so sánh",
            evidence=evidence, url=url,
            recommendation="Gọi session_regenerate_id(true) trong PHP ngay sau khi xác thực đăng nhập thành công.",
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    # =========================================================
    # TRÌNH ĐIỀU KHIỂN CHÍNH (MASTER CONTROLLER)
    # =========================================================

    def run_all_tests(self, export_report: bool = True) -> list[ScanResult]:
        """Chạy toàn bộ 17 DAST test case theo thứ tự V-01 → V-22."""
        print(Fore.WHITE + "BẮT ĐẦU CHIẾN DỊCH RÀ QUÉT TOÀN DIỆN MỤC TIÊU...\n")

        results = [
            # SQLi
            self.test_v01_sqli_login(),
            *self.test_v02_to_v06_sqli_batch(),
            # XSS
            self.test_v07_xss_search(),
            self.test_v08_xss_stored_notes(),
            self.test_v09_xss_reflected_login(),
            self.test_v11_xss_url_params(),
            # Access Control
            self.test_v14_broken_access_control(),
            self.test_v15_idor(),
            # Logic & Input
            self.test_v17_input_validation(),
            self.test_v18_sql_error_disclosure(),
            # Disclosure & Session
            self.test_v19_php_version_disclosure(),
            self.test_v20_password_hash_disclosure(),
            self.test_v22_session_fixation(),
        ]

        failed = sum(1 for r in results if r.status == "FAILED")
        passed = sum(1 for r in results if r.status == "PASSED")

        print(Fore.CYAN + "=" * 70)
        print(Fore.CYAN + "  🏁 DAST SCAN HOÀN TẤT!")
        print(Fore.CYAN + f"  📊 Kết quả: {Fore.RED}{failed} FAILED  {Fore.GREEN}{passed} PASSED  "
              f"{Fore.YELLOW}{len(results) - failed - passed} ERROR/SKIP")
        print(Fore.CYAN + "=" * 70)

        if export_report:
            print(Fore.YELLOW + "\n[*] Đang tạo báo cáo HTML...")
            generator = HtmlReportGenerator()
            output_path = generator.generate(results, target_url=self.base_url, output_dir="./reports")
            print(Fore.GREEN + f"✅ Báo cáo đã được lưu tại: {output_path}")
            print(Fore.WHITE + Style.DIM + "   Mở file bằng trình duyệt để xem chi tiết.\n")

        return results


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="WebSAST Automated Exploitation Framework v2.0"
    )
    parser.add_argument(
        "--target", "-t",
        default="http://localhost/webSAST",
        help="URL mục tiêu cần quét (mặc định: http://localhost/webSAST)",
    )
    parser.add_argument(
        "--web-root", "-w",
        default=r"C:/xampp/htdocs/webSAST",
        help=r"Đường dẫn TUYỆT ĐỐI đến thư mục PHP trên máy (dùng cho SAST, mặc định: C:/xampp/htdocs/webSAST)",
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["poc", "sast", "discover", "all"],
        default="all",
        help=(
            "Chế độ quét:\n"
            "  poc      — 17 DAST test case cố định (V-01→V-22)\n"
            "  sast     — 6 SAST test case đọc file PHP (V-10,V-12,V-13,V-16,V-21,V-23)\n"
            "  discover — Tự động crawl và phát hiện lỗ hổng tự nhiên\n"
            "  all      — Toàn bộ (mặc định)"
        ),
    )
    parser.add_argument(
        "--max-pages",
        type=int, default=30,
        help="Số trang tối đa khi crawl (chỉ dùng cho --mode discover/all, mặc định: 30)",
    )
    args = parser.parse_args()

    TARGET_WEBSITE = args.target
    WEB_ROOT = args.web_root
    all_results: list[ScanResult] = []

    scanner = WebSAST_Scanner(TARGET_WEBSITE)

    # ── DAST (PoC) ─────────────────────────────────────────────
    if args.mode in ("poc", "all"):
        print(Fore.CYAN + "\n" + "=" * 70)
        print(Fore.CYAN + "  [PHASE A] DAST — 17 Test Case Kịch Bản Cố Định")
        print(Fore.CYAN + "=" * 70)
        poc_results = scanner.run_all_tests(export_report=False)
        all_results.extend(poc_results)

    # ── SAST ───────────────────────────────────────────────────
    if args.mode in ("sast", "all"):
        print(Fore.MAGENTA + "\n" + "=" * 70)
        print(Fore.MAGENTA + "  [PHASE B] SAST — 6 Test Case Phân Tích Mã Nguồn Tĩnh")
        print(Fore.MAGENTA + "=" * 70)
        sast = SASTScanner(web_root=WEB_ROOT)
        sast_results = sast.run_all_sast_tests()
        all_results.extend(sast_results)

    # ── Generic Discovery ──────────────────────────────────────
    if args.mode in ("discover", "all"):
        ds = DiscoveryScanner(
            base_url=TARGET_WEBSITE,
            session=scanner.session,
            max_pages=args.max_pages,
        )
        discovery_results = ds.run()
        all_results.extend(discovery_results)

    # ── Xuất báo cáo HTML tổng hợp ────────────────────────────
    print(Fore.YELLOW + "\n[*] Đang tạo báo cáo HTML tổng hợp...")
    generator = HtmlReportGenerator()
    output_path = generator.generate(all_results, target_url=TARGET_WEBSITE, output_dir="./reports")
    print(Fore.GREEN + f"✅ Báo cáo đã được lưu tại: {output_path}")
    print(Fore.WHITE + Style.DIM + "   Mở file bằng trình duyệt để xem chi tiết.\n")