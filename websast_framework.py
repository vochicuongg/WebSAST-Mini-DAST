import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
import re

# Khởi tạo màu sắc cho Terminal
init(autoreset=True)

class WebSAST_Scanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session() 
        print(Fore.CYAN + "="*70)
        print(Fore.CYAN + " 🛡️  WebSAST AUTOMATED EXPLOITATION FRAMEWORK (Mini DAST PoC)")
        print(Fore.CYAN + " 👨‍💻 Developer: Vo Chi Cuong")
        print(Fore.CYAN + "="*70 + "\n")

    def login(self, username, password):
        """Hàm tự động đăng nhập"""
        login_url = f"{self.base_url}/auth/login.php"
        data = {"username": username, "password": password}
        self.session.post(login_url, data=data)

    # ---------------------------------------------------------
    # MODULE 1: INJECTION & XSS
    # ---------------------------------------------------------
    def test_v01_sqli_login(self):
        print(Fore.YELLOW + "[*] Đang test V-01: SQL Injection (Login Auth Bypass)...")
        target_url = f"{self.base_url}/auth/login.php"
        
        temp_session = requests.Session()
        payload = "admin' -- "
        data = {"username": payload, "password": "123"}
        
        response = temp_session.post(target_url, data=data)
        if "Dashboard" in response.text or "Quản trị" in response.text:
            print(Fore.RED + f"    => [FAILED] Lỗ hổng SQLi Bypass tồn tại! Mật khẩu bị vô hiệu hóa bởi payload: {payload}")
        else:
            print(Fore.GREEN + "    => [PASSED] An toàn. Không bị SQLi Bypass tại form Đăng nhập.")
        print("-" * 60)

    def test_v07_xss_search(self):
        print(Fore.YELLOW + "[*] Đang test V-07: XSS Reflected (Search)...")
        payload = "<script>alert('XSS_TEST')</script>"
        # Đường dẫn dựa theo bảng Test case: employees/search.php
        target_url = f"{self.base_url}/employees/search.php?search={payload}"
        
        response = self.session.get(target_url)
        if payload in response.text:
            print(Fore.RED + "    => [FAILED] Lỗ hổng XSS tồn tại! Mã script độc hại in thẳng ra màn hình.")
        else:
            print(Fore.GREEN + "    => [PASSED] An toàn. Dữ liệu đầu vào trang tìm kiếm đã được lọc.")
        print("-" * 60)

    # ---------------------------------------------------------
    # MODULE 2: ACCESS CONTROL & IDOR
    # ---------------------------------------------------------
    def test_v14_broken_access_control(self):
        print(Fore.YELLOW + "[*] Đang test V-14: Broken Access Control (Vượt quyền)...")
        self.login("user", "user123") # Đăng nhập bằng nhân viên thường
        
        admin_url = f"{self.base_url}/admin/users.php"
        response = self.session.get(admin_url)
        
        if "Danh sách người dùng" in response.text or "employee" in response.text:
            print(Fore.RED + "    => [FAILED] Lỗ hổng Vượt quyền! User thường truy cập được trang Admin.")
        elif response.status_code == 403 or "Không có quyền" in response.text:
            print(Fore.GREEN + "    => [PASSED] An toàn. Hệ thống đã chặn truy cập trái phép.")
        print("-" * 60)

    def test_v15_idor(self):
        print(Fore.YELLOW + "[*] Đang test V-15: IDOR (Profile)...")
        self.login("user", "user123") 
        
        # Đường dẫn dựa theo bảng Test case: user/profile.php
        target_url = f"{self.base_url}/user/profile.php?id=1"
        response = self.session.get(target_url)
        
        if "Quản Trị Viên" in response.text or "admin" in response.text.lower():
            print(Fore.RED + "    => [FAILED] Lỗ hổng IDOR! User thường đọc được dữ liệu của Admin (ID=1).")
        else:
            print(Fore.GREEN + "    => [PASSED] An toàn. Không bị lỗi xem trộm hồ sơ.")
        print("-" * 60)

    # ---------------------------------------------------------
    # MODULE 3: INPUT VALIDATION & LOGIC
    # ---------------------------------------------------------
    def test_v17_input_validation(self):
        print(Fore.YELLOW + "[*] Đang test V-17: No Input Validation (Nhập lương âm)...")
        self.login("admin", "admin123") 
        target_url = f"{self.base_url}/employees/add.php"
        
        data = {
            "fullname": "Hacker Logic",
            "email": "hacker@test.com",
            "salary": "-5000000", 
            "status": "1"
        }
        
        response = self.session.post(target_url, data=data)
        if "thành công" in response.text.lower() or "hacker@test.com" in response.text:
            print(Fore.RED + "    => [FAILED] Lỗ hổng Validation! Backend chấp nhận lưu mức lương ÂM.")
        else:
            print(Fore.GREEN + "    => [PASSED] An toàn. Dữ liệu bất hợp lý đã bị chặn.")
        print("-" * 60)

    # ---------------------------------------------------------
    # MODULE 4: INFORMATION DISCLOSURE & SESSION
    # ---------------------------------------------------------
    def test_v19_php_version_disclosure(self):
        print(Fore.YELLOW + "[*] Đang test V-19: PHP Version Disclosure (Footer)...")
        target_url = f"{self.base_url}/auth/login.php" # Footer thường nằm chung ở các trang
        response = requests.get(target_url)
        
        match = re.search(r'PHP\s[78]\.\d\.\d+', response.text)
        if match:
            print(Fore.RED + f"    => [FAILED] Lỗ hổng Information Disclosure! Bắt được: {match.group(0)}")
        else:
            print(Fore.GREEN + "    => [PASSED] An toàn. Chữ ký máy chủ đã được ẩn.")
        print("-" * 60)

    def test_v20_password_hash_disclosure(self):
        print(Fore.YELLOW + "[*] Đang test V-20: Password Hash Disclosure (UI)...")
        self.login("admin", "admin123") 
        target_url = f"{self.base_url}/admin/users.php"
        
        response = self.session.get(target_url)
        # Tìm các chuỗi MD5 (gồm đúng 32 ký tự hex) hiển thị trên HTML
        md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        hashes = md5_pattern.findall(response.text)
        
        if hashes:
            print(Fore.RED + f"    => [FAILED] Lỗ hổng rò rỉ dữ liệu nhạy cảm! Tìm thấy mã Hash trên UI: {hashes[0]}")
        else:
            print(Fore.GREEN + "    => [PASSED] An toàn. Mật khẩu mã hóa không bị in ra giao diện.")
        print("-" * 60)

    def test_v22_session_fixation(self):
        print(Fore.YELLOW + "[*] Đang test V-22: Session Fixation...")
        
        self.session.get(f"{self.base_url}/auth/login.php")
        id_before = self.session.cookies.get('PHPSESSID')
        
        self.login("user", "user123")
        id_after = self.session.cookies.get('PHPSESSID')
        
        if id_before == id_after and id_before is not None:
            print(Fore.RED + "    => [FAILED] Lỗ hổng Session Fixation! Session ID không được làm mới.")
        else:
            print(Fore.GREEN + "    => [PASSED] An toàn. Chìa khóa phiên đã được thay mới.")
        print("-" * 60)

    # =========================================================
    # TRÌNH ĐIỀU KHIỂN CHÍNH (MASTER CONTROLLER)
    # =========================================================
    def run_all_tests(self):
        print(Fore.WHITE + "BẮT ĐẦU CHIẾN DỊCH RÀ QUÉT TOÀN DIỆN MỤC TIÊU...\n")
        
        self.test_v01_sqli_login()
        self.test_v07_xss_search()
        self.test_v14_broken_access_control()
        self.test_v15_idor()
        self.test_v17_input_validation()
        self.test_v19_php_version_disclosure()
        self.test_v20_password_hash_disclosure()
        self.test_v22_session_fixation()
        
        print(Fore.CYAN + "="*70)
        print(Fore.CYAN + " 🏁 QUÁ TRÌNH KIỂM THỬ ĐỘNG ĐÃ HOÀN TẤT!")
        print(Fore.CYAN + "="*70)

# Khởi tạo và chạy Tool
if __name__ == "__main__":
    # Thay bằng link thư mục dự án của bạn (ví dụ: webSAST hoặc tên khác)
    TARGET_WEBSITE = "http://localhost/webSAST" 
    
    scanner = WebSAST_Scanner(TARGET_WEBSITE)
    scanner.run_all_tests()