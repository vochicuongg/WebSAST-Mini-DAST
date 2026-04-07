# 🛡️ WebSAST Automated Exploitation Framework (Mini DAST)

Công cụ kiểm thử bảo mật động (Dynamic Application Security Testing) tự phát triển bằng Python. Đóng vai trò như một cỗ máy phân tích và rà quét lỗ hổng theo hai giai đoạn: Kiểm thử kịch bản định sẵn (PoC) và Rà quét khám phá tự nhiên (Generic Auto-Discovery).

![Phân tích Report](./reports/report_preview.png) *(Hình minh họa báo cáo DAST HTML)*

## 🚀 Tính năng nổi bật

* **🎯 2 Chế độ Rà Két Rõ Ràng:** Khai thác các lỗ hổng đã được nhúng sẵn theo kịch bản (PoC) và Tự động trinh sát (Crawl) đâm payload vào mọi form để tìm lỗ hổng chưa biết.
* **🕷️ Auto-Discovery (Quét Tự Động):** Thu thập toàn bộ URL tĩnh, bóc tách toàn bộ Form (POST/GET), tự động phát hiện tham số.
* **📊 Báo cáo DAST HTML:** Xuất file kết quả theo chuẩn Dashboard bảo mật, phân định rõ khối "Rà quét Kịch bản cố định" và khối "Rà quét Tự Động".
* **🚀 Stateful Session Management:** Tự động duy trì phiên đăng nhập để kiểm thử các lỗi yêu cầu xác thực.
* **✅ Hệ thống 88+ Unit Tests:** Hoạt động ổn định với `pytest` và dễ dàng tích hợp vào luồng CI/CD (GitHub Actions).

---

## 🎯 Danh sách các Lỗ Hổng Hỗ Trợ Rà Quét

Hệ thống được chia làm 2 tầng ưu tiên:

### Phần 1: Tầng Kịch Bản Cố Định (Rà quét 22 Lỗi Chuyên Đề Lab)
1. `V-01`: SQL Injection (Auth Bypass)
2. `V-07`: Reflected XSS
3. `V-14`: Broken Access Control
4. `V-15`: Insecure Direct Object Reference (IDOR)
5. `V-17`: Business Logic Flaw (No Input Validation)
6. `V-19`: PHP Version Disclosure
7. `V-20`: Password Hash Disclosure
8. `V-22`: Session Fixation
*(Các lỗ hổng này được tùy chỉnh và trỏ đích danh vào URL của bộ mã nguồn WebSAST Lab)*

### Phần 2: Tầng Khám Phá Tự Động (Generic Vulnerabilities)
1. `D-01`: SQL Injection trên các form tự phát hiện
2. `D-02`: XSS Reflected trên các trường nhập liệu tự động
3. `D-03`: Thiếu Anti-CSRF Token ở toàn bộ các POST form
4. `D-04`: Open Redirect tại các tham số tiềm năng
5. `D-05`: Thiếu HTTP Security Headers (CSP, X-Frame-Options...)
6. `D-06`: Cấu hình Session Cookie không an toàn
7. `D-07`: Lộ file nhạy cảm và hệ thống (.env, .git, config...)
8. `D-08`: Khai thác Directory Listing
9. `D-09`: Rò rỉ Error & Stack Trace
10. `D-10`: Kẽ hở Brute Force do thiếu Rate Limiting Đăng Nhập
*(Phần này có thể dùng để quét ĐỘC LẬP trên bất kỳ Website nào bên ngoài)*

---

## 🛠️ Cài đặt & Chuẩn bị

Đảm bảo bạn đã có Python 3.9+ trên máy.

```bash
# 1. Clone ứng dụng
git clone https://github.com/vochicuongg/WebSAST-Mini-DAST.git
cd WebSAST-Mini-DAST

# 2. Tạo Virtual Environment (Nên dùng)
python -m venv .venv
# Kích hoạt trên Windows:
.venv\Scripts\activate
# Kích hoạt trên Linux/macOS:
source .venv/bin/activate

# 3. Cài đặt các thư viện cần thiết
pip install -r requirements.txt
pip install -r requirements-dev.txt   # Nếu muốn chạy Unit tests
```

---

## ⚡ Hướng dẫn Sử dụng CLI

Tool hỗ trợ tham số dòng lệnh cực kỳ linh hoạt để quét theo mục đích của bạn.

**1. Chạy quét toàn diện Toàn bộ Dự án (Mặc định)**
Công cụ sẽ chạy Phần 1 (PoC WebSAST) trước, ngay sau đó khởi động Phần 2 (Tự động crawl trang chủ) và tổng hợp thành 1 báo cáo HTML:
```bash
python websast_framework.py --target http://localhost/webSAST
```

**2. Quét website BẤT KỲ bên ngoài (Sức mạnh của DAST)**
Nếu bạn muốn quét một website ngẫu nhiên trên mạng, hãy dùng `--mode discover` để bỏ qua các bài test phụ thuộc vào WebSAST:
```bash
python websast_framework.py --target https://ten-website.com --mode discover
```

**3. Giới hạn số lượng trang Crawl**
Đối với những dự án lớn, để tránh tool leo quá nhiều link, bạn có thể thiết lập số lượng trang được phép lấy dữ liệu:
```bash
python websast_framework.py --target https://ten-website.com --mode discover --max-pages 15
```

**4. Chạy Unit Tests**
Dự án được bảo vệ bởi 88 unit tests không cần kết nối mạng.
```bash
pytest tests/ -v
```

---

## 📄 Cấu trúc Thư mục Chính
* `websast_framework.py`: Module Master điều phối dòng lệnh và quản lý luồng quét.
* `scanner_discovery.py`: Cỗ máy Crawl và bơm payload tự động.
* `report_generator.py`: Hệ thống tạo báo cáo UI/UX bằng HTML độc lập có chèn các class tính toán mức độ nghiêm trọng.
* `tests/`: Kho test tự động Mock HTTP Request để đánh giá Tool.
* `reports/`: Nơi xuất ra thành phẩm HTML.

---
*Dự án thuộc nghiên cứu Chuyên đề An Toàn Thông Tin - Được phát triển cho mục đích giáo dục và Kiểm thử Hợp Pháp.*
