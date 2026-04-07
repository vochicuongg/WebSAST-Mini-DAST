"""
ci_generate_report.py
Script tạo báo cáo HTML mẫu trong pipeline CI/CD mà không cần kết nối tới target thực.
"""
from datetime import datetime
from report_generator import HtmlReportGenerator, ScanResult


def _ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


SAMPLE_RESULTS = [
    ScanResult(
        vuln_id="V-01", name="SQL Injection (Login Auth Bypass)",
        severity="CRITICAL", status="FAILED",
        description="[CI MOCK] Lỗ hổng SQLi Bypass tồn tại! Mật khẩu bị vô hiệu hóa bởi payload: \"admin' -- \"",
        payload="admin' -- ",
        evidence="Trạng thái HTTP: 200 | Title trang sau bypass: Dashboard – EMS\n"
                 "Dashboard Quản trị Hệ thống Nhân sự...",
        url="http://ci-mock-target/webSAST/auth/login.php",
        recommendation="Sử dụng Prepared Statements (PDO/MySQLi). Không nối chuỗi trực tiếp vào SQL.",
        timestamp=_ts(),
    ),
    ScanResult(
        vuln_id="V-07", name="XSS Reflected (Search)",
        severity="HIGH", status="FAILED",
        description="[CI MOCK] Lỗ hổng XSS Reflected tồn tại! Payload được phản chiếu thẳng ra HTML.",
        payload="<script>alert('XSS_TEST')</script>",
        evidence="Payload phát hiện tại vị trí 1042 trong HTML:\n"
                 "...<p><script>alert('XSS_TEST')</script></p>...",
        url="http://ci-mock-target/webSAST/employees/search.php?search=<script>alert('XSS_TEST')</script>",
        recommendation="Áp dụng htmlspecialchars() để encode đầu ra. Triển khai Content-Security-Policy header.",
        timestamp=_ts(),
    ),
    ScanResult(
        vuln_id="V-14", name="Broken Access Control (Privilege Escalation)",
        severity="CRITICAL", status="FAILED",
        description="[CI MOCK] Lỗ hổng Broken Access Control! User thường truy cập được trang Admin.",
        payload="Đăng nhập: user/user123 → Truy cập trực tiếp URL Admin",
        evidence="HTTP Status: 200 | Title: Quản lý người dùng – EMS\nDanh sách người dùng admin employee...",
        url="http://ci-mock-target/webSAST/admin/users.php",
        recommendation="Kiểm tra RBAC ở phía server cho mọi route. Không chỉ kiểm tra ở frontend.",
        timestamp=_ts(),
    ),
    ScanResult(
        vuln_id="V-15", name="IDOR — Insecure Direct Object Reference (Profile)",
        severity="HIGH", status="FAILED",
        description="[CI MOCK] Lỗ hổng IDOR! User thường đọc được dữ liệu của ID=1 (Admin).",
        payload="GET /user/profile.php?id=1",
        evidence="HTTP Status: 200 | Từ khoá: Quản Trị Viên, administrator\nQuản Trị Viên | admin@system.com...",
        url="http://ci-mock-target/webSAST/user/profile.php?id=1",
        recommendation="Validate rằng user chỉ được phép truy cập tài nguyên của chính mình qua session.",
        timestamp=_ts(),
    ),
    ScanResult(
        vuln_id="V-17", name="Business Logic Flaw — No Input Validation (Lương Âm)",
        severity="MEDIUM", status="PASSED",
        description="[CI MOCK] An toàn. Dữ liệu bất hợp lý (lương âm) đã bị từ chối bởi server.",
        payload="{'fullname': 'Hacker Logic Test', 'salary': '-5000000', ...}",
        evidence="N/A",
        url="http://ci-mock-target/webSAST/employees/add.php",
        recommendation="Validate dữ liệu tại Backend: kiểm tra salary > 0 và các ràng buộc nghiệp vụ.",
        timestamp=_ts(),
    ),
    ScanResult(
        vuln_id="V-19", name="PHP Version Disclosure (Headers & Body)",
        severity="LOW", status="PASSED",
        description="[CI MOCK] An toàn. Phiên bản PHP không bị lộ trong response.",
        payload="HTTP GET request — Quan sát headers và body response",
        evidence="N/A",
        url="http://ci-mock-target/webSAST/auth/login.php",
        recommendation="Đặt 'expose_php = Off' trong php.ini. Ẩn header Server trong cấu hình web server.",
        timestamp=_ts(),
    ),
    ScanResult(
        vuln_id="V-20", name="Password Hash Disclosure (UI — MD5/bcrypt/SHA1)",
        severity="HIGH", status="FAILED",
        description="[CI MOCK] Lỗ hổng rò rỉ dữ liệu nhạy cảm! Tìm thấy MD5 hash mật khẩu trên UI.",
        payload="Đăng nhập admin → truy cập /admin/users.php",
        evidence="HTTP Status: 200\nMD5 (2 chuỗi): 5f4dcc3b5aa765d61d8327deb882cf99, 019202...",
        url="http://ci-mock-target/webSAST/admin/users.php",
        recommendation="Không hiển thị hash trên UI. Dùng bcrypt/Argon2 thay vì MD5/SHA1.",
        timestamp=_ts(),
    ),
    ScanResult(
        vuln_id="V-22", name="Session Fixation (PHPSESSID Regeneration)",
        severity="MEDIUM", status="FAILED",
        description="[CI MOCK] Lỗ hổng Session Fixation! Session ID không được làm mới sau khi đăng nhập.",
        payload="GET /auth/login.php → ghi nhận PHPSESSID → POST login → kiểm tra PHPSESSID mới",
        evidence="Session ID trước đăng nhập: hkndgi4f2ptf8cb0\nSession ID sau đăng nhập:  hkndgi4f2ptf8cb0",
        url="http://ci-mock-target/webSAST/auth/login.php",
        recommendation="Gọi session_regenerate_id(true) trong PHP ngay sau khi xác thực đăng nhập thành công.",
        timestamp=_ts(),
    ),
]

if __name__ == "__main__":
    gen = HtmlReportGenerator()
    path = gen.generate(SAMPLE_RESULTS, "http://ci-mock-target/webSAST", "./reports")
    print(f"CI Sample Report generated: {path}")
