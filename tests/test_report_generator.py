"""
tests/test_report_generator.py
Unit tests cho HtmlReportGenerator và ScanResult.
Không cần kết nối mạng — chạy hoàn toàn offline.
"""
import os
import pytest
from datetime import datetime
from report_generator import HtmlReportGenerator, ScanResult


# ─── Helpers ─────────────────────────────────────────────────────────────────

def make_result(
    vuln_id="V-01", name="Test Vuln", severity="HIGH", status="FAILED",
    description="Test description", payload="test_payload",
    evidence="test_evidence", url="http://test.local/",
    recommendation="Fix this issue"
):
    return ScanResult(
        vuln_id=vuln_id, name=name, severity=severity, status=status,
        description=description, payload=payload, evidence=evidence,
        url=url, recommendation=recommendation,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


# ─── ScanResult ───────────────────────────────────────────────────────────────

class TestScanResult:
    def test_creation_all_fields(self):
        r = make_result()
        assert r.vuln_id == "V-01"
        assert r.name == "Test Vuln"
        assert r.severity == "HIGH"
        assert r.status == "FAILED"
        assert r.url == "http://test.local/"

    def test_all_severity_values(self):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            r = make_result(severity=sev)
            assert r.severity == sev

    def test_all_status_values(self):
        for st in ("FAILED", "PASSED", "ERROR", "SKIPPED"):
            r = make_result(status=st)
            assert r.status == st


# ─── HtmlReportGenerator ──────────────────────────────────────────────────────

class TestHtmlReportGenerator:

    def test_generate_creates_file(self, tmp_path):
        gen = HtmlReportGenerator()
        path = gen.generate([make_result()], "http://test.local", str(tmp_path))
        assert os.path.exists(path)
        assert path.endswith(".html")

    def test_filename_contains_timestamp(self, tmp_path):
        gen = HtmlReportGenerator()
        path = gen.generate([make_result()], "http://test.local", str(tmp_path))
        basename = os.path.basename(path)
        assert basename.startswith("report_")
        assert basename.endswith(".html")
        # Filename nên có timestamp dạng YYYYMMDD_HHMMSS
        parts = basename.replace("report_", "").replace(".html", "")
        assert len(parts) == 15  # 8 + 1 + 6

    def test_output_dir_created_automatically(self, tmp_path):
        gen = HtmlReportGenerator()
        new_dir = os.path.join(str(tmp_path), "nested", "reports")
        path = gen.generate([make_result()], "http://test.local", new_dir)
        assert os.path.exists(path)

    def test_html_contains_brand_title(self, tmp_path):
        gen = HtmlReportGenerator()
        path = gen.generate([make_result()], "http://test.local", str(tmp_path))
        html = open(path, encoding="utf-8").read()
        assert "WebSAST DAST Security Report" in html

    def test_html_contains_target_url(self, tmp_path):
        gen = HtmlReportGenerator()
        target = "http://my-custom-target.example.com"
        path = gen.generate([make_result()], target, str(tmp_path))
        html = open(path, encoding="utf-8").read()
        assert target in html

    def test_html_contains_vuln_id(self, tmp_path):
        gen = HtmlReportGenerator()
        path = gen.generate([make_result(vuln_id="V-99")], "http://test.local", str(tmp_path))
        html = open(path, encoding="utf-8").read()
        assert "V-99" in html

    def test_summary_counts_correct(self, tmp_path):
        gen = HtmlReportGenerator()
        results = [
            make_result(status="FAILED"),
            make_result(status="FAILED"),
            make_result(status="PASSED"),
        ]
        path = gen.generate(results, "http://test.local", str(tmp_path))
        html = open(path, encoding="utf-8").read()
        # Trang phải có đủ 3 result cards
        assert html.count("vuln-card") >= 3

    def test_severity_badge_critical(self, tmp_path):
        gen = HtmlReportGenerator()
        path = gen.generate([make_result(severity="CRITICAL")], "http://test.local", str(tmp_path))
        html = open(path, encoding="utf-8").read()
        assert "sev-critical" in html
        assert "CRITICAL" in html

    def test_severity_badge_all_levels(self, tmp_path):
        gen = HtmlReportGenerator()
        for sev, css_class in [
            ("CRITICAL", "sev-critical"),
            ("HIGH", "sev-high"),
            ("MEDIUM", "sev-medium"),
            ("LOW", "sev-low"),
            ("INFO", "sev-info"),
        ]:
            path = gen.generate([make_result(severity=sev)], "http://test.local", str(tmp_path))
            html = open(path, encoding="utf-8").read()
            assert css_class in html, f"CSS class '{css_class}' not found for severity '{sev}'"

    def test_xss_evidence_is_escaped(self, tmp_path):
        """Payload XSS phải bị HTML-escape trong báo cáo, không được render thành tag thật."""
        gen = HtmlReportGenerator()
        xss = "<script>alert('xss')</script>"
        path = gen.generate([make_result(evidence=xss, payload=xss)], "http://test.local", str(tmp_path))
        html = open(path, encoding="utf-8").read()
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_risk_score_all_failed(self, tmp_path):
        gen = HtmlReportGenerator()
        results = [
            make_result(severity="CRITICAL", status="FAILED"),
            make_result(severity="HIGH", status="FAILED"),
        ]
        path = gen.generate(results, "http://test.local", str(tmp_path))
        html = open(path, encoding="utf-8").read()
        assert "CAO" in html

    def test_risk_score_all_passed(self, tmp_path):
        gen = HtmlReportGenerator()
        results = [
            make_result(severity="CRITICAL", status="PASSED"),
            make_result(severity="HIGH", status="PASSED"),
        ]
        path = gen.generate(results, "http://test.local", str(tmp_path))
        html = open(path, encoding="utf-8").read()
        assert "THẤP" in html

    def test_empty_results_does_not_crash(self, tmp_path):
        gen = HtmlReportGenerator()
        path = gen.generate([], "http://test.local", str(tmp_path))
        assert os.path.exists(path)

    def test_status_failed_card_has_class(self, tmp_path):
        gen = HtmlReportGenerator()
        path = gen.generate([make_result(status="FAILED")], "http://test.local", str(tmp_path))
        html = open(path, encoding="utf-8").read()
        assert "vuln-failed" in html

    def test_status_passed_card_no_failed_class(self, tmp_path):
        """Card PASSED không được có class 'vuln-failed' trong phần card div (chỉ có trong CSS)."""
        gen = HtmlReportGenerator()
        path = gen.generate([make_result(status="PASSED")], "http://test.local", str(tmp_path))
        html = open(path, encoding="utf-8").read()
        # CSS definition chứa 'vuln-failed' nhưng card div với status PASSED không được dùng class này
        # Kiểm tra: không có 'class="vuln-card vuln-failed"' trong HTML
        assert 'class="vuln-card vuln-failed"' not in html

    def test_html_is_self_contained(self, tmp_path):
        """File HTML không được chứa link tới CDN bên ngoài."""
        gen = HtmlReportGenerator()
        path = gen.generate([make_result()], "http://test.local", str(tmp_path))
        html = open(path, encoding="utf-8").read()
        assert "cdn.jsdelivr.net" not in html
        assert "unpkg.com" not in html
        assert "googleapis.com" not in html

    def test_recommendation_present(self, tmp_path):
        gen = HtmlReportGenerator()
        rec = "Use bcrypt and prepared statements to fix this."
        path = gen.generate([make_result(recommendation=rec)], "http://test.local", str(tmp_path))
        html = open(path, encoding="utf-8").read()
        assert rec in html

    def test_multiple_results_all_rendered(self, tmp_path):
        gen = HtmlReportGenerator()
        results = [make_result(vuln_id=f"V-{i:02d}", name=f"Test {i}") for i in range(1, 6)]
        path = gen.generate(results, "http://test.local", str(tmp_path))
        html = open(path, encoding="utf-8").read()
        for i in range(1, 6):
            assert f"V-{i:02d}" in html
