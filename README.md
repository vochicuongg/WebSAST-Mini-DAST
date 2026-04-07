<<<<<<< HEAD
# 🛡️ WebSAST Automated Exploitation Framework (Mini DAST PoC)

Công cụ kiểm thử bảo mật động (Dynamic Application Security Testing) tự phát triển bằng Python, đóng vai trò như một PoC để tự động hóa quá trình rà quét lỗ hổng trên hệ thống WebSAST.

## 🚀 Tính năng nổi bật
* **Stateful Session Management:** Tự động duy trì phiên đăng nhập để kiểm thử các lỗi yêu cầu xác thực.
* **Regex Pattern Matching:** Nhận diện rò rỉ dữ liệu nhạy cảm qua biểu thức chính quy.
* **Business Logic Auditing:** Mô phỏng luồng dữ liệu bất hợp lý để bắt lỗi Logic Backend.

## 🎯 Các lỗ hổng hỗ trợ quét tự động
1. V-01: SQL Injection (Auth Bypass)
2. V-07: Reflected XSS 
3. V-14: Broken Access Control
4. V-15: Insecure Direct Object Reference (IDOR)
5. V-17: Business Logic Flaw (No Input Validation)
6. V-19: PHP Version Disclosure
7. V-20: Password Hash Disclosure
8. V-22: Session Fixation

## 🛠️ Cài đặt & Sử dụng
```bash
pip install requests beautifulsoup4 colorama
python websast_framework.py
=======
# 🛡️ WebSAST Automated Exploitation Framework (Mini DAST PoC)

Công cụ kiểm thử bảo mật động (Dynamic Application Security Testing) tự phát triển bằng Python, đóng vai trò như một PoC để tự động hóa quá trình rà quét lỗ hổng trên hệ thống WebSAST.

## 🚀 Tính năng nổi bật
* **Stateful Session Management:** Tự động duy trì phiên đăng nhập để kiểm thử các lỗi yêu cầu xác thực.
* **Regex Pattern Matching:** Nhận diện rò rỉ dữ liệu nhạy cảm qua biểu thức chính quy.
* **Business Logic Auditing:** Mô phỏng luồng dữ liệu bất hợp lý để bắt lỗi Logic Backend.

## 🎯 Các lỗ hổng hỗ trợ quét tự động
1. V-01: SQL Injection (Auth Bypass)
2. V-07: Reflected XSS 
3. V-14: Broken Access Control
4. V-15: Insecure Direct Object Reference (IDOR)
5. V-17: Business Logic Flaw (No Input Validation)
6. V-19: PHP Version Disclosure
7. V-20: Password Hash Disclosure
8. V-22: Session Fixation

## 🛠️ Cài đặt & Sử dụng
```bash
pip install requests beautifulsoup4 colorama
python websast_framework.py
>>>>>>> 2284ce4265305b0e34cebe8ecd71c6431aecdd1e
