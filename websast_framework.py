import requests
import re
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from datetime import datetime
from report_generator import HtmlReportGenerator, ScanResult

# Khởi tạo màu sắc cho Terminal
init(autoreset=True)

EVIDENCE_MAX_LEN = 500  # Giới hạn độ dài evidence trong báo cáo (ký tự)


def _truncate(text: str, limit: int = EVIDENCE_MAX_LEN) -> str:
    """Cắt ngắn chuỗi nếu vượt quá giới hạn và thêm dấu hiệu rõ ràng."""
    text = text.strip()
    if len(text) > limit:
        return text[:limit] + f"\n... [Đã cắt ngắn, tổng {len(text)} ký tự]"
    return text


def _extract_text_snippet(html: str, keyword: str = None, max_len: int = EVIDENCE_MAX_LEN) -> str:
    """Trích xuất đoạn text có nghĩa từ HTML, ưu tiên đoạn chứa keyword."""
    try:
        soup = BeautifulSoup(html, "html.parser")
        # Bỏ script/style
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


class WebSAST_Scanner:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self._print_banner()

    def _print_banner(self):
        print(Fore.CYAN + "=" * 70)
        print(Fore.CYAN + "  🛡️  WebSAST AUTOMATED EXPLOITATION FRAMEWORK (Mini DAST PoC) v1.1")
        print(Fore.CYAN + "=" * 70 + "\n")

    def _now(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _print_result(self, result: ScanResult):
        """In kết quả ra terminal có màu sắc và chi tiết hơn."""
        if result.status == "FAILED":
            color = Fore.RED
            icon = "✗ [FAILED]"
        elif result.status == "PASSED":
            color = Fore.GREEN
            icon = "✓ [PASSED]"
        else:
            color = Fore.YELLOW
            icon = "⚠ [ERROR/SKIP]"

        print(Fore.YELLOW + f"[*] Đang test {result.vuln_id}: {result.name}...")
        print(color + f"    {icon} {result.description}")
        if result.status == "FAILED" and result.evidence and result.evidence != "N/A":
            print(Fore.WHITE + Style.DIM + f"    📌 Evidence: {result.evidence[:200]}{'...' if len(result.evidence) > 200 else ''}")
        if result.payload and result.payload != "N/A":
            print(Fore.WHITE + Style.DIM + f"    💉 Payload: {result.payload}")
        print("-" * 60)

    def login(self, username: str, password: str) -> bool:
        """Đăng nhập và trả về True nếu thành công."""
        login_url = f"{self.base_url}/auth/login.php"
        data = {"username": username, "password": password}
        try:
            resp = self.session.post(login_url, data=data, timeout=10)
            return resp.status_code == 200
        except Exception:
            return False

    # ---------------------------------------------------------
    # MODULE 1: INJECTION & XSS
    # ---------------------------------------------------------
    def test_v01_sqli_login(self) -> ScanResult:
        url = f"{self.base_url}/auth/login.php"
        payload = "admin' -- "
        evidence = "N/A"
        status = "PASSED"
        description = "An toàn. Không bị SQLi Bypass tại form Đăng nhập."

        try:
            temp_session = requests.Session()
            resp = temp_session.post(url, data={"username": payload, "password": "123"}, timeout=10)

            if "Dashboard" in resp.text or "Quản trị" in resp.text or "Xin chào" in resp.text:
                status = "FAILED"
                description = f"Lỗ hổng SQLi Bypass TỒN TẠI! Mật khẩu bị vô hiệu hóa bởi payload: {payload!r}"
                # Trích đoạn title và nội dung trang sau bypass
                soup = BeautifulSoup(resp.text, "html.parser")
                title = soup.find("title")
                evidence = f"Trạng thái HTTP: {resp.status_code} | Title trang sau bypass: {title.text.strip() if title else 'N/A'}\n"
                evidence += _extract_text_snippet(resp.text, keyword="Dashboard")
        except requests.exceptions.ConnectionError:
            status = "ERROR"
            description = "Không thể kết nối tới URL mục tiêu. Hãy đảm bảo server đang chạy."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status = "ERROR"
            description = f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-01", name="SQL Injection (Login Auth Bypass)",
            severity="CRITICAL", status=status, description=description,
            payload=payload, evidence=evidence, url=url,
            recommendation="Sử dụng Prepared Statements (PDO/MySQLi) cho toàn bộ câu query. Không nối chuỗi trực tiếp giá trị người dùng vào SQL.",
            timestamp=self._now()
        )
        self._print_result(result)
        return result

    def test_v07_xss_search(self) -> ScanResult:
        payload = "<script>alert('XSS_TEST')</script>"
        url = f"{self.base_url}/employees/search.php?search={payload}"
        evidence = "N/A"
        status = "PASSED"
        description = "An toàn. Dữ liệu đầu vào trang tìm kiếm đã được encode/lọc."

        try:
            resp = self.session.get(url, timeout=10)
            if payload in resp.text:
                status = "FAILED"
                description = "Lỗ hổng XSS Reflected TỒN TẠI! Mã script độc hại được phản chiếu thẳng ra HTML mà không qua encoding."
                # Tìm đoạn chứa payload trong HTML
                idx = resp.text.find(payload)
                if idx != -1:
                    snippet = resp.text[max(0, idx - 80): idx + len(payload) + 80]
                    evidence = f"Payload phát hiện tại vị trí {idx} trong HTML response:\n{_truncate(snippet)}"
                else:
                    evidence = "Payload được phản chiếu nhưng không xác định được vị trí chính xác."
        except requests.exceptions.ConnectionError:
            status = "ERROR"; description = "Không thể kết nối tới URL mục tiêu."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status = "ERROR"; description = f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-07", name="XSS Reflected (Search)",
            severity="HIGH", status=status, description=description,
            payload=payload, evidence=evidence, url=url,
            recommendation="Áp dụng htmlspecialchars() hoặc htmlentities() để encode đầu ra. Triển khai Content-Security-Policy (CSP) header.",
            timestamp=self._now()
        )
        self._print_result(result)
        return result

    # ---------------------------------------------------------
    # MODULE 2: ACCESS CONTROL & IDOR
    # ---------------------------------------------------------
    def test_v14_broken_access_control(self) -> ScanResult:
        self.login("user", "user123")
        url = f"{self.base_url}/admin/users.php"
        evidence = "N/A"
        status = "PASSED"
        description = "An toàn. Hệ thống đã chặn truy cập trái phép tới trang Admin."

        try:
            resp = self.session.get(url, timeout=10)
            if "Danh sách người dùng" in resp.text or "employee" in resp.text.lower():
                status = "FAILED"
                description = f"Lỗ hổng Broken Access Control TỒN TẠI! User thường truy cập được trang Admin (HTTP {resp.status_code})."
                soup = BeautifulSoup(resp.text, "html.parser")
                title = soup.find("title")
                evidence = f"HTTP Status: {resp.status_code} | Title: {title.text.strip() if title else 'N/A'}\n"
                evidence += _extract_text_snippet(resp.text, keyword="người dùng")
            elif resp.status_code in (403, 401):
                description = f"An toàn. Server trả về HTTP {resp.status_code} — Truy cập bị từ chối đúng cách."
                evidence = f"HTTP Status: {resp.status_code}"
            elif "Không có quyền" in resp.text or "Access Denied" in resp.text:
                description = "An toàn. Server hiển thị thông báo từ chối truy cập."
                evidence = _extract_text_snippet(resp.text, keyword="quyền")
        except requests.exceptions.ConnectionError:
            status = "ERROR"; description = "Không thể kết nối tới URL mục tiêu."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status = "ERROR"; description = f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-14", name="Broken Access Control (Privilege Escalation)",
            severity="CRITICAL", status=status, description=description,
            payload="Đăng nhập: user/user123 → Truy cập trực tiếp URL Admin", evidence=evidence, url=url,
            recommendation="Kiểm tra phân quyền (Role-Based Access Control) ở phía server cho MỌI route. Không chỉ kiểm tra ở frontend.",
            timestamp=self._now()
        )
        self._print_result(result)
        return result

    def test_v15_idor(self) -> ScanResult:
        self.login("user", "user123")
        url = f"{self.base_url}/user/profile.php?id=1"
        evidence = "N/A"
        status = "PASSED"
        description = "An toàn. Không thể xem hồ sơ của người dùng khác (IDOR được chặn)."

        try:
            resp = self.session.get(url, timeout=10)
            # Tìm các chỉ báo dữ liệu admin bị lộ
            indicators = ["Quản Trị Viên", "administrator", "admin@"]
            found = [kw for kw in indicators if kw.lower() in resp.text.lower()]
            if found:
                status = "FAILED"
                description = f"Lỗ hổng IDOR TỒN TẠI! User thường đọc được dữ liệu của ID=1 (Admin). Dấu hiệu: {', '.join(found)}"
                evidence = f"HTTP Status: {resp.status_code} | Từ khoá phát hiện: {', '.join(found)}\n"
                evidence += _extract_text_snippet(resp.text, keyword=found[0])
        except requests.exceptions.ConnectionError:
            status = "ERROR"; description = "Không thể kết nối tới URL mục tiêu."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status = "ERROR"; description = f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-15", name="IDOR — Insecure Direct Object Reference (Profile)",
            severity="HIGH", status=status, description=description,
            payload="GET /user/profile.php?id=1 (thay đổi tham số id trên URL)",
            evidence=evidence, url=url,
            recommendation="Validate rằng user hiện tại chỉ được phép truy cập tài nguyên của chính mình. Dùng session để xác định ownership thay vì tin vào tham số URL.",
            timestamp=self._now()
        )
        self._print_result(result)
        return result

    # ---------------------------------------------------------
    # MODULE 3: INPUT VALIDATION & LOGIC
    # ---------------------------------------------------------
    def test_v17_input_validation(self) -> ScanResult:
        self.login("admin", "admin123")
        url = f"{self.base_url}/employees/add.php"
        payload_data = {"fullname": "Hacker Logic Test", "email": "hacker_logic@test.com", "salary": "-5000000", "status": "1"}
        evidence = "N/A"
        status = "PASSED"
        description = "An toàn. Dữ liệu bất hợp lý (lương âm) đã bị từ chối bởi server."

        try:
            resp = self.session.post(url, data=payload_data, timeout=10)
            success_keywords = ["thành công", "successfully", "hacker_logic@test.com"]
            found = [kw for kw in success_keywords if kw.lower() in resp.text.lower()]
            if found:
                status = "FAILED"
                description = "Lỗ hổng Business Logic TỒN TẠI! Backend chấp nhận lưu mức lương ÂM vào hệ thống."
                evidence = f"HTTP Status: {resp.status_code} | Từ khoá thành công phát hiện: {', '.join(found)}\n"
                evidence += _extract_text_snippet(resp.text, keyword=found[0])
        except requests.exceptions.ConnectionError:
            status = "ERROR"; description = "Không thể kết nối tới URL mục tiêu."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status = "ERROR"; description = f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-17", name="Business Logic Flaw — No Input Validation (Lương Âm)",
            severity="MEDIUM", status=status, description=description,
            payload=str(payload_data), evidence=evidence, url=url,
            recommendation="Validate toàn bộ dữ liệu tại Backend (không chỉ Frontend): kiểm tra salary > 0, email hợp lệ, và các ràng buộc nghiệp vụ khác.",
            timestamp=self._now()
        )
        self._print_result(result)
        return result

    # ---------------------------------------------------------
    # MODULE 4: INFORMATION DISCLOSURE & SESSION
    # ---------------------------------------------------------
    def test_v19_php_version_disclosure(self) -> ScanResult:
        url = f"{self.base_url}/auth/login.php"
        evidence = "N/A"
        status = "PASSED"
        description = "An toàn. Chữ ký máy chủ và phiên bản PHP không bị lộ trong phản hồi."

        try:
            resp = requests.get(url, timeout=10)
            # Kiểm tra trong response body
            body_match = re.search(r'PHP[/\s]([5-9]\.\d+\.\d+)', resp.text)
            # Kiểm tra trong header Server và X-Powered-By
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
                description = f"Lỗ hổng Information Disclosure TỒN TẠI! Phiên bản PHP bị lộ: {'; '.join(leaks)}"
                evidence = f"HTTP Status: {resp.status_code}\n"
                evidence += f"Server: {server_header or 'N/A'}\n"
                evidence += f"X-Powered-By: {powered_by or 'N/A'}\n"
                if body_match:
                    idx = resp.text.find(body_match.group(0))
                    evidence += f"Tìm thấy trong body tại vị trí {idx}: ...{resp.text[max(0,idx-50):idx+100]}..."
        except requests.exceptions.ConnectionError:
            status = "ERROR"; description = "Không thể kết nối tới URL mục tiêu."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status = "ERROR"; description = f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-19", name="PHP Version Disclosure (Headers & Body)",
            severity="LOW", status=status, description=description,
            payload="HTTP GET request — Quan sát headers và body response", evidence=evidence, url=url,
            recommendation="Ẩn phiên bản PHP bằng cách đặt 'expose_php = Off' trong php.ini. Cấu hình web server (Apache/Nginx) để ẩn header Server.",
            timestamp=self._now()
        )
        self._print_result(result)
        return result

    def test_v20_password_hash_disclosure(self) -> ScanResult:
        self.login("admin", "admin123")
        url = f"{self.base_url}/admin/users.php"
        evidence = "N/A"
        status = "PASSED"
        description = "An toàn. Mật khẩu đã mã hóa không bị in ra giao diện người dùng."

        try:
            resp = self.session.get(url, timeout=10)
            # MD5: 32 ký tự hex; bcrypt: bắt đầu bằng $2y$; SHA1: 40 ký tự hex
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
                description = f"Lỗ hổng rò rỉ dữ liệu nhạy cảm TỒN TẠI! Tìm thấy hash mật khẩu trên UI: {'; '.join(all_found)}"
                evidence = f"HTTP Status: {resp.status_code} | Kết quả:\n" + "\n".join(all_found)
        except requests.exceptions.ConnectionError:
            status = "ERROR"; description = "Không thể kết nối tới URL mục tiêu."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status = "ERROR"; description = f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-20", name="Password Hash Disclosure (UI — MD5/bcrypt/SHA1)",
            severity="HIGH", status=status, description=description,
            payload="Đăng nhập admin và truy cập trang /admin/users.php", evidence=evidence, url=url,
            recommendation="Không bao giờ hiển thị hash mật khẩu trên giao diện. Sử dụng bcrypt/Argon2 thay vì MD5/SHA1 để băm mật khẩu.",
            timestamp=self._now()
        )
        self._print_result(result)
        return result

    def test_v22_session_fixation(self) -> ScanResult:
        url = f"{self.base_url}/auth/login.php"
        evidence = "N/A"
        status = "PASSED"
        description = "An toàn. Session ID được làm mới sau khi đăng nhập thành công."

        try:
            # Lấy Session ID TRƯỚC khi đăng nhập
            self.session.get(url, timeout=10)
            id_before = self.session.cookies.get("PHPSESSID")

            self.login("user", "user123")
            id_after = self.session.cookies.get("PHPSESSID")

            evidence = f"Session ID trước đăng nhập: {id_before or 'Không có'}\nSession ID sau đăng nhập:  {id_after or 'Không có'}"

            if id_before is not None and id_before == id_after:
                status = "FAILED"
                description = f"Lỗ hổng Session Fixation TỒN TẠI! Session ID không được làm mới sau khi đăng nhập (PHPSESSID: {id_after})."
            elif id_before is None and id_after is None:
                status = "ERROR"
                description = "Không tìm thấy cookie PHPSESSID. Server có thể không dùng PHP session hoặc không thể kết nối."
        except requests.exceptions.ConnectionError:
            status = "ERROR"; description = "Không thể kết nối tới URL mục tiêu."
            evidence = f"ConnectionError: {url}"
        except Exception as e:
            status = "ERROR"; description = f"Lỗi không xác định: {e}"

        result = ScanResult(
            vuln_id="V-22", name="Session Fixation (PHPSESSID Regeneration)",
            severity="MEDIUM", status=status, description=description,
            payload="GET /auth/login.php (ghi nhận PHPSESSID) → POST login → kiểm tra PHPSESSID mới",
            evidence=evidence, url=url,
            recommendation="Gọi session_regenerate_id(true) trong PHP ngay sau khi xác thực đăng nhập thành công để làm mới Session ID.",
            timestamp=self._now()
        )
        self._print_result(result)
        return result

    # =========================================================
    # TRÌNH ĐIỀU KHIỂN CHÍNH (MASTER CONTROLLER)
    # =========================================================
    def run_all_tests(self):
        print(Fore.WHITE + "BẮT ĐẦU CHIẾN DỊCH RÀ QUÉT TOÀN DIỆN MỤC TIÊU...\n")

        results = [
            self.test_v01_sqli_login(),
            self.test_v07_xss_search(),
            self.test_v14_broken_access_control(),
            self.test_v15_idor(),
            self.test_v17_input_validation(),
            self.test_v19_php_version_disclosure(),
            self.test_v20_password_hash_disclosure(),
            self.test_v22_session_fixation(),
        ]

        failed = sum(1 for r in results if r.status == "FAILED")
        passed = sum(1 for r in results if r.status == "PASSED")

        print(Fore.CYAN + "=" * 70)
        print(Fore.CYAN + "  🏁 QUÁ TRÌNH KIỂM THỬ ĐỘNG ĐÃ HOÀN TẤT!")
        print(Fore.CYAN + f"  📊 Kết quả: {Fore.RED}{failed} FAILED  {Fore.GREEN}{passed} PASSED  "
              f"{Fore.YELLOW}{len(results) - failed - passed} ERROR/SKIP")
        print(Fore.CYAN + "=" * 70)

        # Xuất báo cáo HTML
        print(Fore.YELLOW + "\n[*] Đang tạo báo cáo HTML...")
        generator = HtmlReportGenerator()
        output_path = generator.generate(results, target_url=self.base_url, output_dir="./reports")
        print(Fore.GREEN + f"✅ Báo cáo đã được lưu tại: {output_path}")
        print(Fore.WHITE + Style.DIM + "   Mở file bằng trình duyệt để xem chi tiết.\n")

        return results


# Khởi tạo và chạy Tool
if __name__ == "__main__":
    # Thay bằng link thư mục dự án của bạn (ví dụ: webSAST hoặc tên khác)
    TARGET_WEBSITE = "http://localhost/webSAST"

    scanner = WebSAST_Scanner(TARGET_WEBSITE)
    scanner.run_all_tests()