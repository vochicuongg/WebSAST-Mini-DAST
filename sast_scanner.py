"""
sast_scanner.py
Static Application Security Testing (SAST) Module
Đọc file mã nguồn PHP bằng os + re để phát hiện lỗ hổng tĩnh.
"""

import os
import re
from datetime import datetime
from colorama import Fore, Style
from report_generator import ScanResult

EVIDENCE_MAX_LEN = 500


def _truncate(text: str, limit: int = EVIDENCE_MAX_LEN) -> str:
    text = str(text).strip()
    if len(text) > limit:
        return text[:limit] + f"\n... [Đã cắt ngắn, tổng {len(text)} ký tự]"
    return text


def _read_file(path: str) -> str | None:
    """Đọc file an toàn, trả về None nếu không tìm thấy."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except (FileNotFoundError, PermissionError):
        return None


def _find_pattern_lines(content: str, pattern: str, flags: int = re.IGNORECASE) -> list[str]:
    """Trả về danh sách các dòng khớp với regex pattern."""
    results = []
    for i, line in enumerate(content.splitlines(), 1):
        if re.search(pattern, line, flags):
            results.append(f"  Dòng {i:4d}: {line.strip()}")
    return results


class SASTScanner:
    """
    SAST Scanner: đọc file PHP mã nguồn để phát hiện lỗ hổng tĩnh.
    Không cần web server đang chạy.
    """

    def __init__(self, web_root: str):
        """
        Args:
            web_root: Đường dẫn tuyệt đối đến thư mục gốc của dự án PHP trên máy.
                      VD: r"C:/xampp/htdocs/webSAST"
        """
        self.web_root = web_root.rstrip("/\\")
        self._print_banner()

    def _print_banner(self):
        print(Fore.MAGENTA + "=" * 70)
        print(Fore.MAGENTA + "  🔬 WebSAST SAST ENGINE — Phân Tích Mã Nguồn Tĩnh")
        print(Fore.MAGENTA + "=" * 70 + "\n")

    def _now(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _path(self, relative: str) -> str:
        """Ghép web_root + đường dẫn tương đối."""
        return os.path.join(self.web_root, relative.lstrip("/\\"))

    def _print_result(self, result: ScanResult):
        if result.status == "FAILED":
            color, icon = Fore.RED, "✗ [FAILED]"
        elif result.status == "PASSED":
            color, icon = Fore.GREEN, "✓ [PASSED]"
        else:
            color, icon = Fore.YELLOW, "⚠ [ERROR/SKIP]"

        print(Fore.YELLOW + f"[*] Đang phân tích {result.vuln_id}: {result.name}...")
        print(color + f"    {icon} {result.description}")
        if result.status == "FAILED" and result.evidence not in ("N/A", ""):
            preview = result.evidence[:250] + ("..." if len(result.evidence) > 250 else "")
            print(Fore.WHITE + Style.DIM + f"    📌 Evidence:\n{preview}")
        print("-" * 60)

    # ─── V-10: DOM XSS ────────────────────────────────────────────

    def test_v10_dom_xss(self, js_relative_path: str = "assets/js/main.js") -> ScanResult:
        """
        [SAST] Tìm các sink DOM XSS nguy hiểm: innerHTML, document.write,
        eval(), location.href gán thẳng từ user input (location.search/hash).
        """
        target_path = self._path(js_relative_path)
        content = _read_file(target_path)

        if content is None:
            return ScanResult(
                vuln_id="V-10", name="DOM XSS (Phân Tích File JavaScript)",
                severity="HIGH", status="ERROR",
                description=f"Không tìm thấy file: {target_path}",
                payload="SAST — Đọc file JS", evidence="N/A",
                url=f"file://{target_path}",
                recommendation="Đảm bảo đường dẫn web_root và tên file JS đúng.",
                timestamp=self._now(), scan_type="poc",
            )

        # Các sink nguy hiểm được phát hiện
        sink_patterns = [
            (r"\.innerHTML\s*=", "Gán innerHTML trực tiếp"),
            (r"document\.write\s*\(", "document.write()"),
            (r"\beval\s*\(", "eval()"),
            (r"location\.href\s*=\s*.*(location\.|window\.name|document\.)", "Gán href từ nguồn user-controlled"),
            (r"\$\s*\(\s*location\.(search|hash)", "jQuery selector từ URL"),
        ]

        found_sinks = []
        for pattern, label in sink_patterns:
            lines = _find_pattern_lines(content, pattern)
            if lines:
                found_sinks.append(f"► {label}:\n" + "\n".join(lines[:5]))

        if found_sinks:
            status = "FAILED"
            description = f"Lỗ hổng DOM XSS TỒN TẠI! Tìm thấy {len(found_sinks)} loại sink nguy hiểm trong {js_relative_path}."
            evidence = _truncate("\n\n".join(found_sinks))
        else:
            status = "PASSED"
            description = f"An toàn. Không phát hiện sink DOM XSS trong {js_relative_path}."
            evidence = "N/A"

        result = ScanResult(
            vuln_id="V-10", name="DOM XSS (Phân Tích File JavaScript)",
            severity="HIGH", status=status, description=description,
            payload="SAST — Regex: innerHTML / document.write / eval / location.href",
            evidence=evidence, url=f"file://{target_path}",
            recommendation=(
                "Tránh dùng innerHTML để chèn nội dung từ URL/user input. "
                "Dùng textContent thay thế. Với jQuery dùng .text() thay vì .html(). "
                "Không bao giờ eval() dữ liệu từ nguồn ngoài."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    # ─── V-12: Hardcoded DB Password ─────────────────────────────

    def test_v12_hardcoded_db_password(self, config_relative_path: str = "config/db.php") -> ScanResult:
        """
        [SAST] Phát hiện mật khẩu DB được hardcode trực tiếp trong file PHP.
        """
        target_path = self._path(config_relative_path)
        content = _read_file(target_path)

        if content is None:
            return ScanResult(
                vuln_id="V-12", name="Hardcoded DB Password (config/db.php)",
                severity="CRITICAL", status="ERROR",
                description=f"Không tìm thấy file: {target_path}",
                payload="SAST — Đọc file", evidence="N/A",
                url=f"file://{target_path}",
                recommendation="Kiểm tra lại đường dẫn web_root.",
                timestamp=self._now(), scan_type="poc",
            )

        # Tìm dòng gán biến password/pass không trống
        patterns = [
            r"""\$(?:db_?pass(?:word)?|password|passwd)\s*=\s*['"][^'"]{1,}['"]""",
            r"""define\s*\(\s*['"](?:DB_PASS(?:WORD)?|PASSWORD)['"]\s*,\s*['"][^'"]{1,}['"]\s*\)""",
        ]
        found_lines = []
        for p in patterns:
            found_lines += _find_pattern_lines(content, p)

        if found_lines:
            status = "FAILED"
            description = f"Lỗ hổng Hardcoded Password TỒN TẠI! Mật khẩu DB được viết cứng trong {config_relative_path}."
            evidence = _truncate("\n".join(found_lines[:10]))
        else:
            status = "PASSED"
            description = f"An toàn. Không phát hiện mật khẩu DB viết cứng trong {config_relative_path}."
            evidence = "N/A"

        result = ScanResult(
            vuln_id="V-12", name="Hardcoded DB Password (config/db.php)",
            severity="CRITICAL", status=status, description=description,
            payload="SAST — Regex: $db_pass / $password / define('DB_PASS'...",
            evidence=evidence, url=f"file://{target_path}",
            recommendation=(
                "Di chuyển thông tin nhạy cảm (DB host, user, pass) vào biến môi trường (.env). "
                "Sử dụng thư viện như vlucas/phpdotenv. KHÔNG commit file chứa credentials lên Git."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    # ─── V-13: Hardcoded App Secret ──────────────────────────────

    def test_v13_hardcoded_app_secret(self, config_relative_path: str = "config/db.php") -> ScanResult:
        """
        [SAST] Tìm secret key / API key / JWT secret được hardcode trong PHP.
        """
        target_path = self._path(config_relative_path)
        content = _read_file(target_path)

        if content is None:
            return ScanResult(
                vuln_id="V-13", name="Hardcoded App Secret / API Key",
                severity="CRITICAL", status="ERROR",
                description=f"Không tìm thấy file: {target_path}",
                payload="SAST — Đọc file", evidence="N/A",
                url=f"file://{target_path}",
                recommendation="Kiểm tra lại đường dẫn web_root.",
                timestamp=self._now(), scan_type="poc",
            )

        patterns = [
            r"""\$(?:secret(?:_key)?|app_key|jwt_secret|api_key|token_secret)\s*=\s*['"][^'"]{6,}['"]""",
            r"""define\s*\(\s*['"](?:SECRET(?:_KEY)?|APP_KEY|JWT_SECRET|API_KEY)['"]\s*,\s*['"][^'"]{6,}['"]\s*\)""",
        ]
        found_lines = []
        for p in patterns:
            found_lines += _find_pattern_lines(content, p)

        if found_lines:
            status = "FAILED"
            description = (
                f"Lỗ hổng Hardcoded App Secret TỒN TẠI! "
                f"Secret key / API key được viết cứng trong {config_relative_path}."
            )
            evidence = _truncate("\n".join(found_lines[:10]))
        else:
            status = "PASSED"
            description = f"An toàn. Không phát hiện secret key viết cứng trong {config_relative_path}."
            evidence = "N/A"

        result = ScanResult(
            vuln_id="V-13", name="Hardcoded App Secret / API Key",
            severity="CRITICAL", status=status, description=description,
            payload="SAST — Regex: $secret_key / define('SECRET_KEY'...",
            evidence=evidence, url=f"file://{target_path}",
            recommendation=(
                "Lưu secret key vào biến môi trường hoặc vault (AWS Secrets Manager, HashiCorp Vault). "
                "Thêm file .env vào .gitignore ngay lập tức. Rotate lại khóa nếu đã bị lộ."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    # ─── V-16: No CSRF Protection ─────────────────────────────────

    def test_v16_no_csrf_protection(self, scan_dirs: list[str] | None = None) -> ScanResult:
        """
        [SAST] Duyệt nhiều file PHP, tìm form POST không có CSRF token input.
        """
        if scan_dirs is None:
            scan_dirs = ["employees", "admin", "auth", "user"]

        files_with_post_form = []   # (filepath, dòng form)
        files_missing_csrf = []     # (filepath, dòng form)

        csrf_token_re = re.compile(
            r"""<input[^>]+name\s*=\s*['"](?:csrf[_-]?token|_token|authenticity_token|nonce)['"]""",
            re.IGNORECASE,
        )
        post_form_re = re.compile(
            r"""<form[^>]+method\s*=\s*['"]post['"]""",
            re.IGNORECASE,
        )

        for scan_dir in scan_dirs:
            dir_path = self._path(scan_dir)
            if not os.path.isdir(dir_path):
                continue
            for fname in os.listdir(dir_path):
                if not fname.endswith(".php"):
                    continue
                fpath = os.path.join(dir_path, fname)
                content = _read_file(fpath)
                if content is None:
                    continue
                if post_form_re.search(content):
                    rel = os.path.relpath(fpath, self.web_root)
                    files_with_post_form.append(rel)
                    if not csrf_token_re.search(content):
                        files_missing_csrf.append(rel)

        if not files_with_post_form:
            return ScanResult(
                vuln_id="V-16", name="No CSRF Protection (Form POST)",
                severity="HIGH", status="ERROR",
                description=f"Không tìm thấy file PHP nào có POST form trong: {', '.join(scan_dirs)}.",
                payload="SAST — Quét thư mục PHP", evidence="N/A",
                url=f"file://{self.web_root}",
                recommendation="Kiểm tra lại đường dẫn web_root và tên thư mục.",
                timestamp=self._now(), scan_type="poc",
            )

        if files_missing_csrf:
            status = "FAILED"
            description = (
                f"Lỗ hổng CSRF TỒN TẠI! {len(files_missing_csrf)}/{len(files_with_post_form)} "
                f"file có form POST đang thiếu CSRF token."
            )
            evidence = _truncate(
                f"Tổng form POST: {len(files_with_post_form)} | Thiếu token: {len(files_missing_csrf)}\n"
                "File thiếu CSRF token:\n" + "\n".join(f"  - {f}" for f in files_missing_csrf[:15])
            )
        else:
            status = "PASSED"
            description = (
                f"An toàn. Tất cả {len(files_with_post_form)} form POST đều có CSRF token."
            )
            evidence = f"Đã kiểm tra {len(files_with_post_form)} file: " + ", ".join(files_with_post_form[:10])

        result = ScanResult(
            vuln_id="V-16", name="No CSRF Protection (Form POST)",
            severity="HIGH", status=status, description=description,
            payload="SAST — Regex: <form method=post> không có <input name=csrf_token>",
            evidence=evidence, url=f"file://{self.web_root}",
            recommendation=(
                "Thêm CSRF token ẩn vào mọi form POST: "
                "<input type='hidden' name='csrf_token' value='<?= $_SESSION[\"csrf_token\"] ?>'>. "
                "Xác minh token phía server trước mỗi hành động ghi dữ liệu."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    # ─── V-21: Weak MD5 Hashing ───────────────────────────────────

    def test_v21_weak_md5_hashing(self, scan_dirs: list[str] | None = None) -> ScanResult:
        """
        [SAST] Tìm hàm md5() / sha1() được dùng để hash mật khẩu trong PHP.
        """
        if scan_dirs is None:
            scan_dirs = ["auth", "admin", "includes", "config"]

        md5_pattern = re.compile(r"""\bmd5\s*\(""", re.IGNORECASE)
        sha1_pattern = re.compile(r"""\bsha1\s*\(""", re.IGNORECASE)
        password_context_re = re.compile(
            r"""(password|pass|pwd|hash|mot_de_passe)""", re.IGNORECASE
        )

        found_uses = []

        for scan_dir in scan_dirs:
            dir_path = self._path(scan_dir)
            if not os.path.isdir(dir_path):
                continue
            for fname in os.listdir(dir_path):
                if not fname.endswith(".php"):
                    continue
                fpath = os.path.join(dir_path, fname)
                content = _read_file(fpath)
                if content is None:
                    continue
                rel = os.path.relpath(fpath, self.web_root)

                for i, line in enumerate(content.splitlines(), 1):
                    if (md5_pattern.search(line) or sha1_pattern.search(line)):
                        # Chỉ báo động nếu dòng đó có liên quan đến password
                        context = content.splitlines()[max(0, i - 5): i + 3]
                        context_str = "\n".join(context)
                        if password_context_re.search(context_str):
                            found_uses.append(
                                f"  {rel} — Dòng {i}: {line.strip()}"
                            )

        if found_uses:
            status = "FAILED"
            description = (
                f"Lỗ hổng Weak Hashing TỒN TẠI! Tìm thấy {len(found_uses)} chỗ dùng "
                f"md5()/sha1() để xử lý mật khẩu."
            )
            evidence = _truncate("Dòng code nguy hiểm:\n" + "\n".join(found_uses[:10]))
        else:
            status = "PASSED"
            description = "An toàn. Không phát hiện md5()/sha1() trong ngữ cảnh xử lý mật khẩu."
            evidence = N_A = "N/A"

        result = ScanResult(
            vuln_id="V-21", name="Weak Password Hashing — MD5/SHA1",
            severity="HIGH", status=status, description=description,
            payload="SAST — Regex: md5() / sha1() gần context 'password'",
            evidence=evidence, url=f"file://{self.web_root}",
            recommendation=(
                "Thay thế hoàn toàn md5/sha1 bằng password_hash($pass, PASSWORD_BCRYPT) "
                "và xác thực bằng password_verify(). Thuật toán bcrypt/Argon2 có cost factor "
                "điều chỉnh được và chống rainbow table tốt hơn MD5 hàng nghìn lần."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    # ─── V-23: Password in Session ───────────────────────────────

    def test_v23_password_in_session(self, auth_relative_path: str = "auth/login.php") -> ScanResult:
        """
        [SAST] Phát hiện việc lưu mật khẩu plaintext vào $_SESSION.
        """
        target_path = self._path(auth_relative_path)
        content = _read_file(target_path)

        if content is None:
            return ScanResult(
                vuln_id="V-23", name="Password Stored in Session (auth/login.php)",
                severity="HIGH", status="ERROR",
                description=f"Không tìm thấy file: {target_path}",
                payload="SAST — Đọc file", evidence="N/A",
                url=f"file://{target_path}",
                recommendation="Kiểm tra lại đường dẫn web_root và tên file.",
                timestamp=self._now(), scan_type="poc",
            )

        # Tìm $_SESSION['...password...'] = $anything  hoặc Session::put('password', ...)
        patterns = [
            r"""\$_SESSION\s*\[\s*['"][^'"]*(?:pass(?:word)?|pwd|mot_de_passe)[^'"]*['"]\s*\]\s*=""",
            r"""session_register\s*\(\s*['"][^'"]*pass[^'"]*['"]\s*\)""",
        ]
        found_lines = []
        for p in patterns:
            found_lines += _find_pattern_lines(content, p)

        if found_lines:
            status = "FAILED"
            description = (
                "Lỗ hổng Password in Session TỒN TẠI! "
                "Mật khẩu người dùng đang được lưu vào $_SESSION — "
                "có thể bị lộ qua Session Hijacking hoặc log server."
            )
            evidence = _truncate("\n".join(found_lines[:10]))
        else:
            status = "PASSED"
            description = f"An toàn. Không phát hiện mật khẩu được lưu vào $_SESSION trong {auth_relative_path}."
            evidence = "N/A"

        result = ScanResult(
            vuln_id="V-23", name="Password Stored in Session (auth/login.php)",
            severity="HIGH", status=status, description=description,
            payload="SAST — Regex: $_SESSION['password'] = ...",
            evidence=evidence, url=f"file://{target_path}",
            recommendation=(
                "Không bao giờ lưu mật khẩu (dù đã hash) vào session. "
                "Chỉ lưu các thông tin không nhạy cảm như user_id, role, username. "
                "Nếu cần xác thực lại, yêu cầu người dùng nhập lại mật khẩu."
            ),
            timestamp=self._now(), scan_type="poc",
        )
        self._print_result(result)
        return result

    # ─── Master Runner ─────────────────────────────────────────────

    def run_all_sast_tests(self) -> list[ScanResult]:
        """Chạy toàn bộ 6 SAST test case theo thứ tự V-10 → V-23."""
        results = [
            self.test_v10_dom_xss(),
            self.test_v12_hardcoded_db_password(),
            self.test_v13_hardcoded_app_secret(),
            self.test_v16_no_csrf_protection(),
            self.test_v21_weak_md5_hashing(),
            self.test_v23_password_in_session(),
        ]

        failed = sum(1 for r in results if r.status == "FAILED")
        passed = sum(1 for r in results if r.status == "PASSED")

        print(Fore.MAGENTA + "=" * 70)
        print(Fore.MAGENTA + "  🏁 SAST SCAN HOÀN TẤT!")
        print(
            Fore.MAGENTA
            + f"  📊 Kết quả: {Fore.RED}{failed} FAILED  {Fore.GREEN}{passed} PASSED  "
            + f"{Fore.YELLOW}{len(results) - failed - passed} ERROR/SKIP"
        )
        print(Fore.MAGENTA + "=" * 70 + "\n")

        return results
