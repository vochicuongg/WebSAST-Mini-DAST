"""
scanner_discovery.py
Generic DAST Scanner — Chế độ Tự Động Khám Phá (Auto-Discovery Mode)
Tự động crawl, phát hiện form/endpoint và kiểm thử lỗ hổng trên bất kỳ web app nào.
"""

import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set

import requests
from bs4 import BeautifulSoup
from colorama import Fore

from report_generator import ScanResult

EVIDENCE_MAX_LEN = 500

SQLI_PAYLOADS = ["'", "1' OR '1'='1", "1 AND SLEEP(0)--"]
SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "warning: mysqli", "sqlstate",
    "ora-", "pg_query", "unclosed quotation", "you have an error in your sql",
    "supplied argument is not a valid mysql",
]
XSS_PAYLOAD = "<script>alert('XSS_DAST_GENERIC')</script>"
CSRF_TOKEN_NAMES = ["csrf", "csrf_token", "_token", "token", "nonce", "_csrf", "authenticity_token"]
REDIRECT_PARAMS = ["redirect", "next", "url", "return", "goto", "dest", "redir"]
SENSITIVE_FILES = [
    "/.git/HEAD", "/.env", "/phpinfo.php", "/info.php",
    "/config.php", "/db.php", "/backup.sql", "/db.sql",
    "/.htaccess", "/composer.json", "/phpmyadmin/",
]
SENSITIVE_DIRS = ["/uploads/", "/assets/", "/logs/", "/backup/", "/temp/", "/tmp/"]
SECURITY_HEADERS = {
    "X-Frame-Options": "Chống Clickjacking",
    "Content-Security-Policy": "Chống XSS nâng cao",
    "X-Content-Type-Options": "Chống MIME-sniffing",
    "Strict-Transport-Security": "HSTS — Ép dùng HTTPS",
    "Referrer-Policy": "Kiểm soát Referrer",
}


@dataclass
class FormInfo:
    source_url: str
    action: str
    method: str   # "GET" or "POST"
    fields: List[dict] = field(default_factory=list)


def _truncate(text: str, limit: int = EVIDENCE_MAX_LEN) -> str:
    text = str(text).strip()
    if len(text) > limit:
        return text[:limit] + f"\n... [đã cắt ngắn, tổng {len(text)} ký tự]"
    return text


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class DiscoveryScanner:
    """
    Generic DAST Scanner: tự động crawl + phát hiện form + kiểm thử lỗ hổng.
    Không cần biết trước cấu trúc của web app.
    """

    def __init__(self, base_url: str, session: requests.Session,
                 max_pages: int = 30, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.max_pages = max_pages
        self.timeout = timeout
        self.discovered_urls: Set[str] = set()
        self.discovered_forms: List[FormInfo] = []

    # ─── Helpers ────────────────────────────────────────────────

    def _is_same_domain(self, url: str) -> bool:
        try:
            base = urllib.parse.urlparse(self.base_url)
            other = urllib.parse.urlparse(url)
            return other.netloc == base.netloc or other.netloc == ""
        except Exception:
            return False

    def _normalize_url(self, href: str, source: str) -> Optional[str]:
        try:
            if not href or href.startswith(("javascript:", "mailto:", "#")):
                return None
            url = urllib.parse.urljoin(source, href).split("#")[0]
            return url if self._is_same_domain(url) else None
        except Exception:
            return None

    def _print_result(self, result: ScanResult):
        color = Fore.RED if result.status == "FAILED" else \
                Fore.GREEN if result.status == "PASSED" else Fore.YELLOW
        icon = "✗ [FAILED]" if result.status == "FAILED" else \
               "✓ [PASSED]" if result.status == "PASSED" else "⚠ [ERROR/SKIP]"
        print(Fore.YELLOW + f"  [*] {result.vuln_id}: {result.name}")
        print(color + f"      {icon} {result.description[:130]}")
        if result.status == "FAILED" and result.evidence not in ("N/A", ""):
            print(Fore.WHITE + f"      📌 Evidence: {result.evidence[:160]}")
        print("  " + "-" * 60)

    # ─── Phase 1: Passive Recon ─────────────────────────────────

    def crawl_site(self) -> Set[str]:
        """Crawl site tự động, trả về set URL đã khám phá."""
        visited: Set[str] = set()
        queue = [self.base_url]
        print(Fore.CYAN + f"  [Recon] Bắt đầu crawl (tối đa {self.max_pages} trang)...")

        while queue and len(visited) < self.max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                visited.add(url)
                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue
                soup = BeautifulSoup(resp.text, "html.parser")
                for tag in soup.find_all("a", href=True):
                    norm = self._normalize_url(tag["href"], url)
                    if norm and norm not in visited and norm not in queue:
                        queue.append(norm)
            except Exception:
                visited.add(url)

        print(Fore.CYAN + f"  [Recon] Đã khám phá {len(visited)} trang.")
        self.discovered_urls = visited
        return visited

    def fetch_all_forms(self, urls: Set[str]) -> List[FormInfo]:
        """Thu thập tất cả form từ các URL đã crawl."""
        all_forms: List[FormInfo] = []
        for url in urls:
            try:
                resp = self.session.get(url, timeout=self.timeout)
                soup = BeautifulSoup(resp.text, "html.parser")
                for form in soup.find_all("form"):
                    action = urllib.parse.urljoin(url, form.get("action", url))
                    method = form.get("method", "get").upper()
                    fields = [
                        {"name": inp.get("name"), "type": inp.get("type", "text"),
                         "value": inp.get("value", "")}
                        for inp in form.find_all(["input", "textarea", "select"])
                        if inp.get("name")
                    ]
                    if fields:
                        all_forms.append(FormInfo(source_url=url, action=action,
                                                  method=method, fields=fields))
            except Exception:
                continue

        print(Fore.CYAN + f"  [Recon] Tìm thấy {len(all_forms)} form trên site.")
        self.discovered_forms = all_forms
        return all_forms

    def recon_metadata(self) -> dict:
        """Đọc robots.txt, sitemap.xml để tìm thêm đường dẫn ẩn."""
        extra_urls: Set[str] = set()
        info: dict = {}
        for path, pattern in [
            ("/robots.txt", r"(?i)Disallow:\s*(.+)"),
            ("/sitemap.xml", r"<loc>(.*?)</loc>"),
        ]:
            try:
                resp = requests.get(f"{self.base_url}{path}", timeout=self.timeout)
                if resp.status_code == 200:
                    info[path] = resp.text[:300]
                    for match in re.findall(pattern, resp.text)[:20]:
                        norm = urllib.parse.urljoin(self.base_url, match.strip())
                        if self._is_same_domain(norm):
                            extra_urls.add(norm)
            except Exception:
                pass
        info["extra_urls"] = extra_urls
        return info

    # ─── Phase 2: Active Scan ────────────────────────────────────

    def test_sqli_generic(self, forms: List[FormInfo]) -> ScanResult:
        """Kiểm tra SQL Injection trên tất cả form và field tìm được."""
        status, evidence, affected = "PASSED", "N/A", []
        skip_types = ("hidden", "submit", "button", "checkbox", "radio", "file")

        for form in forms:
            for fld in form.fields:
                if fld.get("type") in skip_types:
                    continue
                for payload in SQLI_PAYLOADS:
                    data = {f["name"]: f.get("value", "test") for f in form.fields}
                    data[fld["name"]] = payload
                    try:
                        resp = (self.session.post(form.action, data=data, timeout=self.timeout, allow_redirects=False)
                                if form.method == "POST"
                                else self.session.get(form.action, params=data, timeout=self.timeout, allow_redirects=False))
                        for err in SQLI_ERRORS:
                            if err in resp.text.lower():
                                affected.append(
                                    f"URL: {form.source_url} | Field: {fld['name']} | Payload: {payload}")
                                status = "FAILED"
                                break
                    except Exception:
                        continue
                if status == "FAILED":
                    break
            if status == "FAILED":
                break

        description = (f"Lỗ hổng SQL Injection (Generic) TỒN TẠI! Phát hiện tại {len(affected)} điểm."
                       if status == "FAILED"
                       else "An toàn. Không phát hiện SQL Injection trên các form đã quét.")
        evidence = _truncate("Chi tiết:\n" + "\n".join(affected[:3])) if affected else "N/A"

        return ScanResult(
            vuln_id="D-01", name="SQL Injection (Generic — Tự Động Khám Phá)",
            severity="CRITICAL", status=status, description=description,
            payload="', 1' OR '1'='1", evidence=evidence, url=self.base_url,
            recommendation="Sử dụng Prepared Statements cho tất cả câu query. Không bao giờ nối chuỗi user input vào SQL.",
            timestamp=_now(), scan_type='discover',
        )

    def test_xss_generic(self, forms: List[FormInfo]) -> ScanResult:
        """Kiểm tra XSS Reflected trên tất cả form và field tìm được."""
        status, evidence, affected = "PASSED", "N/A", []
        skip_types = ("hidden", "submit", "button", "file")

        for form in forms:
            for fld in form.fields:
                if fld.get("type") in skip_types:
                    continue
                data = {f["name"]: f.get("value", "test") for f in form.fields}
                data[fld["name"]] = XSS_PAYLOAD
                try:
                    resp = (self.session.post(form.action, data=data, timeout=self.timeout)
                            if form.method == "POST"
                            else self.session.get(form.action, params=data, timeout=self.timeout))
                    if XSS_PAYLOAD in resp.text:
                        idx = resp.text.find(XSS_PAYLOAD)
                        snippet = resp.text[max(0, idx - 60):idx + len(XSS_PAYLOAD) + 60]
                        affected.append(f"URL: {form.source_url} | Field: {fld['name']}\nSnippet: {snippet[:150]}")
                        status = "FAILED"
                except Exception:
                    continue

        description = (f"Lỗ hổng XSS Reflected (Generic) TỒN TẠI! Payload phản chiếu trong {len(affected)} field."
                       if status == "FAILED"
                       else "An toàn. Không phát hiện Reflected XSS trên các form đã quét.")
        evidence = _truncate("Chi tiết:\n" + "\n---\n".join(affected[:3])) if affected else "N/A"

        return ScanResult(
            vuln_id="D-02", name="XSS Reflected (Generic — Tự Động Khám Phá)",
            severity="HIGH", status=status, description=description,
            payload=XSS_PAYLOAD, evidence=evidence, url=self.base_url,
            recommendation="Áp dụng htmlspecialchars() khi echo dữ liệu người dùng. Thêm Content-Security-Policy header.",
            timestamp=_now(), scan_type='discover',
        )

    def test_csrf_generic(self, forms: List[FormInfo]) -> ScanResult:
        """Kiểm tra CSRF token trên tất cả form POST."""
        post_forms = [f for f in forms if f.method == "POST"]
        if not post_forms:
            return ScanResult(
                vuln_id="D-03", name="CSRF — Thiếu Anti-CSRF Token (Generic)",
                severity="HIGH", status="SKIPPED",
                description="Không tìm thấy form POST nào để kiểm tra.",
                payload="N/A", evidence="N/A", url=self.base_url,
                recommendation="Đảm bảo tất cả form POST có CSRF token.",
                timestamp=_now(), scan_type='discover',
            )

        vulnerable = []
        for form in post_forms:
            names = [f["name"].lower() for f in form.fields]
            has_csrf = any(tok in name for name in names for tok in CSRF_TOKEN_NAMES)
            if not has_csrf:
                vulnerable.append(form.source_url)

        if vulnerable:
            status = "FAILED"
            description = f"Lỗ hổng CSRF TỒN TẠI! {len(vulnerable)}/{len(post_forms)} form POST thiếu CSRF token."
            evidence = _truncate("Form thiếu token:\n" + "\n".join(vulnerable[:5]))
        else:
            status = "PASSED"
            description = f"An toàn. Tất cả {len(post_forms)} form POST đều có CSRF token."
            evidence = "N/A"

        return ScanResult(
            vuln_id="D-03", name="CSRF — Thiếu Anti-CSRF Token (Generic)",
            severity="HIGH", status=status, description=description,
            payload="Kiểm tra <input type='hidden' name='csrf_token'>",
            evidence=evidence, url=self.base_url,
            recommendation="Thêm CSRF token ngẫu nhiên vào mọi form POST và xác minh phía server trước khi xử lý.",
            timestamp=_now(), scan_type='discover',
        )

    def test_open_redirect(self, urls: Set[str]) -> ScanResult:
        """Kiểm tra Open Redirect trên các URL có tham số redirect."""
        evil = "https://evil-attacker-dast.com"
        affected = []

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            rp = next((p for p in params if p.lower() in REDIRECT_PARAMS), None)
            if not rp:
                continue
            new_params = {**params, rp: [evil]}
            test_url = parsed._replace(query=urllib.parse.urlencode(new_params, doseq=True)).geturl()
            try:
                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code in (301, 302, 303, 307, 308) and evil in resp.headers.get("Location", ""):
                    affected.append(f"URL: {test_url}\nLocation: {resp.headers['Location']}")
            except Exception:
                continue

        if not affected:
            for path in ["/auth/login.php", "/login.php", "/login"]:
                try:
                    resp = self.session.get(
                        f"{self.base_url}{path}?redirect={evil}&next={evil}",
                        timeout=self.timeout, allow_redirects=False)
                    if resp.status_code in (301, 302, 303, 307, 308) and evil in resp.headers.get("Location", ""):
                        affected.append(f"URL: {self.base_url}{path}\nLocation: {resp.headers['Location']}")
                except Exception:
                    continue

        status = "FAILED" if affected else "PASSED"
        description = ("Lỗ hổng Open Redirect TỒN TẠI! Tham số redirect không được kiểm tra."
                       if status == "FAILED"
                       else "An toàn. Không phát hiện lỗ hổng Open Redirect.")
        evidence = _truncate("\n".join(affected[:3])) if affected else "N/A"

        return ScanResult(
            vuln_id="D-04", name="Open Redirect (Generic — Tham Số Tự Động Phát Hiện)",
            severity="MEDIUM", status=status, description=description,
            payload=f"?redirect={evil}",
            evidence=evidence, url=self.base_url,
            recommendation="Chỉ cho phép redirect nội bộ domain. Dùng whitelist các đường dẫn được phép.",
            timestamp=_now(), scan_type='discover',
        )

    # ─── Phase 3: Generic Checks ─────────────────────────────────

    def test_security_headers(self) -> ScanResult:
        """Kiểm tra 5 HTTP Security Headers quan trọng."""
        try:
            resp = requests.get(self.base_url, timeout=self.timeout)
            missing = [f"{h} ({d})" for h, d in SECURITY_HEADERS.items() if h not in resp.headers]
            if len(missing) >= 3:
                status = "FAILED"
                description = f"Thiếu {len(missing)}/5 security header quan trọng."
                evidence = _truncate("Header bị thiếu:\n" + "\n".join(f"  - {h}" for h in missing))
            else:
                status = "PASSED"
                description = f"An toàn. Chỉ thiếu {len(missing)}/5 header (ngưỡng cảnh báo: 3+)."
                evidence = f"Thiếu: {', '.join(missing)}" if missing else "Đầy đủ các header."
        except requests.exceptions.ConnectionError:
            status, description, evidence = "ERROR", "Không thể kết nối.", "ConnectionError"
        except Exception as e:
            status, description, evidence = "ERROR", str(e), "N/A"

        return ScanResult(
            vuln_id="D-05", name="Thiếu HTTP Security Headers",
            severity="MEDIUM", status=status, description=description,
            payload="HTTP GET — Kiểm tra response headers",
            evidence=evidence, url=self.base_url,
            recommendation=(
                "Thêm các header bảo mật: X-Frame-Options: DENY, Content-Security-Policy, "
                "X-Content-Type-Options: nosniff, Strict-Transport-Security, Referrer-Policy."
            ),
            timestamp=_now(), scan_type='discover',
        )

    def test_cookie_flags(self) -> ScanResult:
        """Kiểm tra cookie session có đủ flag bảo mật."""
        raw_cookie = ""
        for path in ["/auth/login.php", "/login.php", "/login"]:
            try:
                resp = requests.post(
                    f"{self.base_url}{path}",
                    data={"username": "user", "password": "user123"},
                    timeout=self.timeout,
                )
                raw_cookie = resp.headers.get("Set-Cookie", "")
                if raw_cookie:
                    break
            except Exception:
                continue

        missing = [flag for flag in ("HttpOnly", "Secure", "SameSite")
                   if flag.lower() not in raw_cookie.lower()]

        if not raw_cookie:
            status = "ERROR"
            description = "Không tìm thấy Set-Cookie header. Đường dẫn login có thể khác mặc định."
            evidence = "Không có Set-Cookie header trong response."
        elif missing:
            status = "FAILED"
            description = f"Cookie session thiếu {len(missing)} flag bảo mật: {', '.join(missing)}."
            evidence = _truncate(f"Set-Cookie: {raw_cookie[:300]}\nFlag bị thiếu: {', '.join(missing)}")
        else:
            status = "PASSED"
            description = "An toàn. Cookie session có đầy đủ HttpOnly, Secure, SameSite."
            evidence = f"Set-Cookie: {raw_cookie[:200]}"

        return ScanResult(
            vuln_id="D-06", name="Cookie Session Thiếu Flag Bảo Mật",
            severity="MEDIUM", status=status, description=description,
            payload="POST /login → kiểm tra Set-Cookie header",
            evidence=evidence, url=self.base_url,
            recommendation="Thêm flag vào session cookie: HttpOnly (ngăn JS đọc), Secure (chỉ gửi qua HTTPS), SameSite=Strict.",
            timestamp=_now(), scan_type='discover',
        )

    def test_sensitive_files(self) -> ScanResult:
        """Tìm kiếm file/thư mục nhạy cảm bị lộ công khai."""
        found = []
        for path in SENSITIVE_FILES:
            try:
                resp = requests.get(f"{self.base_url}{path}", timeout=self.timeout,
                                    allow_redirects=False)
                if resp.status_code == 200 and len(resp.text.strip()) > 10:
                    not_error = not any(kw in resp.text.lower()
                                        for kw in ["not found", "404", "error", "không tìm thấy"])
                    if not_error:
                        snippet = resp.text[:120].strip().replace("\n", " ")
                        found.append(f"{self.base_url}{path} → HTTP 200 | {snippet}")
            except Exception:
                continue

        status = "FAILED" if found else "PASSED"
        description = (f"LỖ HỔNG NGHIÊM TRỌNG! Tìm thấy {len(found)} file/thư mục nhạy cảm bị lộ."
                       if found
                       else f"An toàn. Đã kiểm tra {len(SENSITIVE_FILES)} đường dẫn, không có file nào bị lộ.")
        evidence = _truncate("File bị lộ:\n" + "\n".join(found[:5])) if found else "N/A"

        return ScanResult(
            vuln_id="D-07", name="Lộ File Nhạy Cảm (.git, .env, configs)",
            severity="CRITICAL", status=status, description=description,
            payload=f"GET {', '.join(SENSITIVE_FILES[:4])}...",
            evidence=evidence, url=self.base_url,
            recommendation="Đảm bảo .env, .git, config.php không nằm trong thư mục public. Chặn truy cập bằng cấu hình web server.",
            timestamp=_now(), scan_type='discover',
        )

    def test_directory_listing(self) -> ScanResult:
        """Kiểm tra Directory Listing trên các thư mục phổ biến."""
        found = []
        for path in SENSITIVE_DIRS:
            try:
                resp = requests.get(f"{self.base_url}{path}", timeout=self.timeout)
                if resp.status_code == 200 and any(
                    kw in resp.text.lower()
                    for kw in ["index of /", "directory listing", "parent directory", "[dir]"]
                ):
                    found.append(f"{self.base_url}{path} → Directory Listing đang bật")
            except Exception:
                continue

        status = "FAILED" if found else "PASSED"
        description = (f"Lỗ hổng Directory Listing TỒN TẠI! {len(found)} thư mục bị lộ nội dung."
                       if found
                       else "An toàn. Không có thư mục nào bật Directory Listing.")
        evidence = _truncate("\n".join(found)) if found else f"Đã kiểm tra: {', '.join(SENSITIVE_DIRS)}"

        return ScanResult(
            vuln_id="D-08", name="Directory Listing Đang Bật",
            severity="MEDIUM", status=status, description=description,
            payload=f"GET {', '.join(SENSITIVE_DIRS)}",
            evidence=evidence, url=self.base_url,
            recommendation="Thêm 'Options -Indexes' vào .htaccess hoặc cấu hình Nginx để tắt Directory Listing.",
            timestamp=_now(), scan_type='discover',
        )

    def test_error_disclosure(self) -> ScanResult:
        """Kích hoạt lỗi để xem server có lộ stack trace / đường dẫn tuyệt đối không."""
        triggers = [
            f"{self.base_url}/?id='",
            f"{self.base_url}/dast_nonexistent_path_xyz_9999",
            f"{self.base_url}/?page=../../../etc/passwd",
        ]
        found = []
        for url in triggers:
            try:
                resp = requests.get(url, timeout=self.timeout)
                text = resp.text
                tl = text.lower()
                indicators = []
                if "stack trace" in tl:
                    indicators.append("Stack trace")
                if re.search(r'[Cc]:\\|/var/www|/home/\w|/usr/local', text):
                    indicators.append("Đường dẫn tuyệt đối")
                if "fatal error" in tl and "php" in tl:
                    indicators.append("PHP Fatal Error chi tiết")
                if "warning:" in tl and ("mysql" in tl or "pdo" in tl):
                    indicators.append("MySQL/PDO Warning chi tiết")
                if indicators:
                    found.append(f"URL: {url}\nLộ thông tin: {', '.join(indicators)}")
            except Exception:
                continue

        status = "FAILED" if found else "PASSED"
        description = ("Lỗ hổng Error Disclosure TỒN TẠI! Server lộ thông tin kỹ thuật khi gặp lỗi."
                       if found
                       else "An toàn. Server không lộ stack trace hay đường dẫn khi gặp lỗi.")
        evidence = _truncate("\n---\n".join(found[:3])) if found else f"Đã thử {len(triggers)} URL kích hoạt lỗi."

        return ScanResult(
            vuln_id="D-09", name="Lộ Thông Tin Lỗi & Stack Trace",
            severity="LOW", status=status, description=description,
            payload="GET /?id=' | /dast_nonexistent | /?page=../../../etc/passwd",
            evidence=evidence, url=self.base_url,
            recommendation="Đặt 'display_errors = Off' trong php.ini. Ghi lỗi vào file log thay vì hiển thị ra màn hình.",
            timestamp=_now(), scan_type='discover',
        )

    def test_brute_force_protection(self) -> ScanResult:
        """Kiểm tra có Rate Limiting / Brute Force protection không."""
        login_url = None
        for path in ["/auth/login.php", "/login.php", "/login"]:
            try:
                resp = requests.get(f"{self.base_url}{path}", timeout=self.timeout)
                if resp.status_code == 200 and any(
                    kw in resp.text.lower() for kw in ["password", "username", "login", "đăng nhập"]
                ):
                    login_url = f"{self.base_url}{path}"
                    break
            except Exception:
                continue

        if not login_url:
            return ScanResult(
                vuln_id="D-10", name="Brute Force — Không Có Rate Limiting",
                severity="HIGH", status="ERROR",
                description="Không tìm thấy trang đăng nhập để kiểm tra.",
                payload="N/A", evidence="N/A", url=self.base_url,
                recommendation="Triển khai rate limiting và account lockout trên trang đăng nhập.",
                timestamp=_now(), scan_type='discover',
            )

        statuses, blocked = [], False
        for i in range(10):
            try:
                resp = requests.post(
                    login_url,
                    data={"username": "dast_brute_test", "password": f"wrongpass_{i}"},
                    timeout=self.timeout,
                )
                statuses.append(resp.status_code)
                if resp.status_code in (429, 403, 423):
                    blocked = True
                    break
                if any(kw in resp.text.lower()
                       for kw in ["too many", "blocked", "captcha", "locked", "account locked"]):
                    blocked = True
                    break
            except Exception:
                break

        if blocked:
            status = "PASSED"
            description = f"An toàn. Phát hiện cơ chế chặn sau {len(statuses)} lần thử."
            evidence = f"Status codes: {statuses}\nĐã bị chặn sau {len(statuses)} request."
        else:
            status = "FAILED"
            description = "Lỗ hổng Brute Force TỒN TẠI! 10 request đăng nhập sai liên tiếp không bị chặn."
            evidence = _truncate(
                f"Login URL: {login_url}\n"
                f"10 request đều trả về: {set(statuses)}\n"
                f"Không có dấu hiệu rate limiting."
            )

        return ScanResult(
            vuln_id="D-10", name="Brute Force — Không Có Rate Limiting Đăng Nhập",
            severity="HIGH", status=status, description=description,
            payload="10x POST /login với mật khẩu sai",
            evidence=evidence, url=self.base_url,
            recommendation="Triển khai Account Lockout, Rate Limiting (HTTP 429), và CAPTCHA sau nhiều lần thất bại.",
            timestamp=_now(), scan_type='discover',
        )

    # ─── Main Entry Point ─────────────────────────────────────────

    def run(self) -> List[ScanResult]:
        print(Fore.CYAN + "\n" + "=" * 70)
        print(Fore.CYAN + "  🔍 DISCOVERY SCAN — BẮT ĐẦU TRINH SÁT VÀ KHAI THÁC TỰ ĐỘNG")
        print(Fore.CYAN + "=" * 70)

        # Phase 1
        print(Fore.YELLOW + "\n[Phase 1/3] Trinh sát thụ động (Crawl + Phát hiện Form)...")
        recon = self.recon_metadata()
        urls = self.crawl_site()
        urls.update(recon.get("extra_urls", set()))
        forms = self.fetch_all_forms(urls)

        # Phase 2
        print(Fore.YELLOW + "\n[Phase 2/3] Tấn công chủ động trên các form đã phát hiện...")
        phase2 = [
            self.test_sqli_generic(forms),
            self.test_xss_generic(forms),
            self.test_csrf_generic(forms),
            self.test_open_redirect(urls),
        ]
        for r in phase2:
            self._print_result(r)

        # Phase 3
        print(Fore.YELLOW + "\n[Phase 3/3] Kiểm tra tổng quan toàn site...")
        phase3 = [
            self.test_security_headers(),
            self.test_cookie_flags(),
            self.test_sensitive_files(),
            self.test_directory_listing(),
            self.test_error_disclosure(),
            self.test_brute_force_protection(),
        ]
        for r in phase3:
            self._print_result(r)

        all_results = phase2 + phase3
        failed = sum(1 for r in all_results if r.status == "FAILED")
        passed = sum(1 for r in all_results if r.status == "PASSED")
        print(Fore.CYAN + "\n" + "=" * 70)
        print(Fore.CYAN + f"  🏁 DISCOVERY SCAN HOÀN TẤT: {Fore.RED}{failed} FAILED  {Fore.GREEN}{passed} PASSED")
        print(Fore.CYAN + "=" * 70)

        return all_results
