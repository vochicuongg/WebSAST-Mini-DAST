import os
from datetime import datetime
from dataclasses import dataclass


@dataclass
class ScanResult:
    vuln_id: str
    name: str
    severity: str       # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    status: str         # "FAILED" | "PASSED" | "ERROR" | "SKIPPED"
    description: str
    payload: str
    evidence: str
    url: str
    recommendation: str
    timestamp: str
    scan_type: str = "poc"


class HtmlReportGenerator:
    """Tạo báo cáo HTML tự chứa từ danh sách ScanResult."""

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def generate(self, results: list, target_url: str, output_dir: str = "./reports") -> str:
        """Tạo file HTML và trả về đường dẫn file."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(output_dir, f"report_{timestamp_str}.html")

        html = self._render_html(results, target_url, timestamp_str)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        return output_path

    def _get_severity_style(self, severity: str) -> tuple:
        """Trả về (CSS class, màu hex) cho từng mức độ nghiêm trọng."""
        mapping = {
            "CRITICAL": ("sev-critical", "#ff4d4d"),
            "HIGH":     ("sev-high",     "#ff8c42"),
            "MEDIUM":   ("sev-medium",   "#ffc107"),
            "LOW":      ("sev-low",      "#66bb6a"),
            "INFO":     ("sev-info",     "#78909c"),
        }
        return mapping.get(severity.upper(), ("sev-info", "#78909c"))

    def _render_html(self, results: list, target_url: str, timestamp_str: str) -> str:
        total = len(results)
        failed = sum(1 for r in results if r.status == "FAILED")
        passed = sum(1 for r in results if r.status == "PASSED")
        errors = sum(1 for r in results if r.status not in ("FAILED", "PASSED"))

        # Tính điểm rủi ro đơn giản
        weight = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
        risk_score = sum(weight.get(r.severity, 0) for r in results if r.status == "FAILED")
        max_score = sum(weight.get(r.severity, 0) for r in results)
        risk_pct = int((risk_score / max_score * 100) if max_score > 0 else 0)

        if risk_pct >= 70:
            risk_label, risk_color = "CAO", "#ff4d4d"
        elif risk_pct >= 40:
            risk_label, risk_color = "TRUNG BÌNH", "#ffc107"
        else:
            risk_label, risk_color = "THẤP", "#66bb6a"

        def render_rows(subset: list) -> str:
            rows_html = ""
            for r in subset:
                sev_class, sev_color = self._get_severity_style(r.severity)
                status_class = "status-failed" if r.status == "FAILED" else \
                               "status-passed" if r.status == "PASSED" else "status-error"
                status_icon = "✗" if r.status == "FAILED" else \
                              "✓" if r.status == "PASSED" else "⚠"
                
                evidence_escaped = (r.evidence or "N/A").replace("<", "&lt;").replace(">", "&gt;")
                payload_escaped = (r.payload or "N/A").replace("<", "&lt;").replace(">", "&gt;")

                rows_html += f"""
                <div class="vuln-card {'vuln-failed' if r.status == 'FAILED' else ''}">
                    <div class="vuln-header">
                        <div class="vuln-title-group">
                            <span class="vuln-id">{r.vuln_id}</span>
                            <span class="vuln-name">{r.name}</span>
                        </div>
                        <div class="vuln-badges">
                            <span class="badge {sev_class}">{r.severity}</span>
                            <span class="badge {status_class}">{status_icon} {r.status}</span>
                        </div>
                    </div>
                    <div class="vuln-body">
                        <div class="info-grid">
                            <div class="info-item">
                                <span class="info-label">🎯 URL Mục Tiêu</span>
                                <code class="info-value url-value">{r.url}</code>
                            </div>
                            <div class="info-item">
                                <span class="info-label">🕐 Thời Gian</span>
                                <span class="info-value">{r.timestamp}</span>
                            </div>
                        </div>
                        <div class="info-item full-width">
                            <span class="info-label">📋 Mô Tả</span>
                            <p class="info-value desc-text">{r.description}</p>
                        </div>
                        <div class="info-item full-width">
                            <span class="info-label">💉 Payload / Input</span>
                            <code class="info-value code-block">{payload_escaped}</code>
                        </div>
                        <div class="info-item full-width">
                            <span class="info-label">🔍 Bằng Chứng (Evidence)</span>
                            <code class="info-value code-block evidence-block">{evidence_escaped}</code>
                        </div>
                        <div class="info-item full-width recommendation-box">
                            <span class="info-label">🛠️ Khuyến Nghị Vá Lỗi</span>
                            <p class="info-value">{r.recommendation}</p>
                        </div>
                    </div>
                </div>
                """
            return rows_html

        poc_results = [r for r in results if getattr(r, 'scan_type', 'poc') == 'poc']
        discover_results = [r for r in results if getattr(r, 'scan_type', 'poc') == 'discover']

        final_rows_html = ""
        if poc_results:
            final_rows_html += f'<h2 class="section-title">Phần 1: Rà Quét 22 Lỗ Hổng Chuyên Đề (Kịch Bản Cố Định)</h2>\n'
            final_rows_html += render_rows(poc_results)
        if discover_results:
            final_rows_html += f'<h2 class="section-title" style="margin-top: 32px;">Phần 2: Khám Phá Tự Động (Lỗ Hổng Tự Nhiên)</h2>\n'
            final_rows_html += render_rows(discover_results)
        if not poc_results and not discover_results:
            final_rows_html = render_rows(results)

        report_time = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S").strftime("%d/%m/%Y %H:%M:%S")

        return f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSAST DAST Report — {report_time}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-card: #1c2128;
            --bg-card-failed: #1f1015;
            --border: #30363d;
            --border-failed: #5a1e28;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --text-muted: #484f58;
            --accent: #58a6ff;
            --green: #3fb950;
            --red: #f85149;
            --orange: #ff8c42;
            --yellow: #e3b341;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            font-size: 14px;
            line-height: 1.6;
        }}
        /* ── Header ── */
        .report-header {{
            background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #1a1f2e 100%);
            border-bottom: 1px solid var(--border);
            padding: 40px 0 30px;
            position: relative;
            overflow: hidden;
        }}
        .report-header::before {{
            content: '';
            position: absolute; inset: 0;
            background: radial-gradient(ellipse at 20% 50%, rgba(88,166,255,0.05) 0%, transparent 60%),
                        radial-gradient(ellipse at 80% 20%, rgba(248,81,73,0.05) 0%, transparent 60%);
        }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 0 24px; position: relative; }}
        .header-top {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; flex-wrap: wrap; }}
        .header-brand {{ display: flex; align-items: center; gap: 14px; }}
        .shield-icon {{
            width: 52px; height: 52px;
            background: linear-gradient(135deg, #1f6feb, #388bfd);
            border-radius: 14px;
            display: flex; align-items: center; justify-content: center;
            font-size: 26px;
            box-shadow: 0 4px 20px rgba(56,139,253,0.3);
        }}
        .header-title h1 {{
            font-size: 22px; font-weight: 700;
            background: linear-gradient(90deg, #e6edf3, #58a6ff);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }}
        .header-title p {{ color: var(--text-secondary); font-size: 13px; margin-top: 3px; }}
        .meta-block {{ text-align: right; }}
        .meta-block p {{ color: var(--text-secondary); font-size: 12px; line-height: 1.8; }}
        .meta-block code {{ color: var(--accent); background: rgba(88,166,255,0.08); padding: 1px 6px; border-radius: 4px; font-size: 12px; }}

        /* ── Summary Cards ── */
        .summary-section {{ padding: 32px 0 24px; }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px; margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            transition: border-color 0.2s;
        }}
        .stat-card:hover {{ border-color: var(--accent); }}
        .stat-value {{ font-size: 36px; font-weight: 700; line-height: 1; margin-bottom: 6px; }}
        .stat-label {{ color: var(--text-secondary); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
        .stat-total .stat-value {{ color: var(--text-primary); }}
        .stat-failed .stat-value {{ color: var(--red); }}
        .stat-passed .stat-value {{ color: var(--green); }}
        .stat-error .stat-value {{ color: var(--orange); }}
        .risk-bar-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px; padding: 20px;
            grid-column: span 2;
        }}
        .risk-bar-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }}
        .risk-label-text {{ font-size: 13px; color: var(--text-secondary); }}
        .risk-score-text {{ font-size: 18px; font-weight: 700; }}
        .risk-bar-track {{
            height: 10px; background: var(--bg-card);
            border-radius: 99px; overflow: hidden;
        }}
        .risk-bar-fill {{
            height: 100%; border-radius: 99px;
            transition: width 0.8s ease;
        }}

        /* ── Severity Legend ── */
        .legend {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 8px; }}
        .legend-item {{ display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text-secondary); }}
        .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; }}

        /* ── Vuln Cards ── */
        .vulns-section {{ padding-bottom: 48px; }}
        .section-title {{
            font-size: 16px; font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 16px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border);
        }}
        .vuln-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px; margin-bottom: 16px;
            overflow: hidden;
            transition: box-shadow 0.2s, border-color 0.2s;
        }}
        .vuln-card:hover {{ box-shadow: 0 4px 24px rgba(0,0,0,0.4); }}
        .vuln-failed {{ background: var(--bg-card-failed); border-color: var(--border-failed); }}
        .vuln-failed:hover {{ border-color: var(--red); }}
        .vuln-header {{
            display: flex; justify-content: space-between; align-items: center;
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
            flex-wrap: wrap; gap: 10px;
        }}
        .vuln-title-group {{ display: flex; align-items: center; gap: 10px; }}
        .vuln-id {{
            background: rgba(88,166,255,0.1); color: var(--accent);
            border: 1px solid rgba(88,166,255,0.3);
            padding: 3px 10px; border-radius: 6px;
            font-size: 12px; font-weight: 700; font-family: monospace;
            white-space: nowrap;
        }}
        .vuln-name {{ font-weight: 600; font-size: 15px; }}
        .vuln-badges {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        /* Badges */
        .badge {{ padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px; white-space: nowrap; }}
        .sev-critical {{ background: rgba(255,77,77,0.15); color: #ff4d4d; border: 1px solid rgba(255,77,77,0.4); }}
        .sev-high     {{ background: rgba(255,140,66,0.15); color: #ff8c42; border: 1px solid rgba(255,140,66,0.4); }}
        .sev-medium   {{ background: rgba(255,193,7,0.15);  color: #ffc107; border: 1px solid rgba(255,193,7,0.4); }}
        .sev-low      {{ background: rgba(102,187,106,0.15);color: #66bb6a; border: 1px solid rgba(102,187,106,0.4); }}
        .sev-info     {{ background: rgba(120,144,156,0.15);color: #90a4ae; border: 1px solid rgba(120,144,156,0.4); }}
        .status-failed {{ background: rgba(248,81,73,0.15); color: #f85149; border: 1px solid rgba(248,81,73,0.4); }}
        .status-passed {{ background: rgba(63,185,80,0.15); color: #3fb950; border: 1px solid rgba(63,185,80,0.4); }}
        .status-error  {{ background: rgba(255,140,66,0.15);color: #ff8c42; border: 1px solid rgba(255,140,66,0.4); }}

        /* Vuln Body */
        .vuln-body {{ padding: 16px 20px; display: flex; flex-direction: column; gap: 14px; }}
        .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }}
        @media (max-width: 600px) {{ .info-grid {{ grid-template-columns: 1fr; }} }}
        .info-item {{ display: flex; flex-direction: column; gap: 5px; }}
        .full-width {{ grid-column: 1 / -1; }}
        .info-label {{ font-size: 11px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }}
        .info-value {{ color: var(--text-primary); font-size: 13px; }}
        .url-value {{ color: var(--accent); word-break: break-all; }}
        .desc-text {{ color: var(--text-secondary); line-height: 1.7; }}
        .code-block {{
            display: block; background: #0d1117;
            border: 1px solid var(--border);
            border-radius: 8px; padding: 10px 14px;
            font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
            font-size: 12px; color: #e6edf3;
            word-break: break-all; white-space: pre-wrap;
        }}
        .evidence-block {{ color: #a5d6ff; min-height: 40px; }}
        .recommendation-box {{
            background: rgba(63,185,80,0.05);
            border: 1px solid rgba(63,185,80,0.2);
            border-radius: 8px; padding: 12px 14px;
        }}
        .recommendation-box .info-label {{ color: rgba(63,185,80,0.7); }}
        .recommendation-box .info-value {{ color: #a8d8a9; line-height: 1.7; }}

        /* ── Footer ── */
        .report-footer {{
            border-top: 1px solid var(--border);
            padding: 20px 0;
            text-align: center;
            color: var(--text-muted);
            font-size: 12px;
        }}
        .report-footer a {{ color: var(--accent); text-decoration: none; }}
        .report-footer a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>

<header class="report-header">
    <div class="container">
        <div class="header-top">
            <div class="header-brand">
                <div class="shield-icon">🛡️</div>
                <div class="header-title">
                    <h1>WebSAST DAST Security Report</h1>
                    <p>Automated Exploitation Framework — Mini DAST PoC v1.1</p>
                </div>
            </div>
            <div class="meta-block">
                <p>🕐 Thời gian: <strong>{report_time}</strong></p>
                <p>🎯 Mục tiêu: <code>{target_url}</code></p>
            </div>
        </div>
    </div>
</header>

<main class="container">
    <!-- Summary -->
    <section class="summary-section">
        <div class="summary-grid">
            <div class="stat-card stat-total">
                <div class="stat-value">{total}</div>
                <div class="stat-label">Tổng Kiểm Thử</div>
            </div>
            <div class="stat-card stat-failed">
                <div class="stat-value">{failed}</div>
                <div class="stat-label">Lỗ Hổng Phát Hiện</div>
            </div>
            <div class="stat-card stat-passed">
                <div class="stat-value">{passed}</div>
                <div class="stat-label">Đã An Toàn</div>
            </div>
            <div class="stat-card stat-error">
                <div class="stat-value">{errors}</div>
                <div class="stat-label">Lỗi / Bỏ Qua</div>
            </div>
            <div class="risk-bar-card">
                <div class="risk-bar-header">
                    <span class="risk-label-text">📊 Điểm Rủi Ro Tổng Thể</span>
                    <span class="risk-score-text" style="color:{risk_color};">{risk_pct}% — {risk_label}</span>
                </div>
                <div class="risk-bar-track">
                    <div class="risk-bar-fill" style="width:{risk_pct}%; background:linear-gradient(90deg,{risk_color},{risk_color}88);"></div>
                </div>
            </div>
        </div>
        <div class="legend">
            <span class="legend-item"><span class="legend-dot" style="background:#ff4d4d;"></span>CRITICAL</span>
            <span class="legend-item"><span class="legend-dot" style="background:#ff8c42;"></span>HIGH</span>
            <span class="legend-item"><span class="legend-dot" style="background:#ffc107;"></span>MEDIUM</span>
            <span class="legend-item"><span class="legend-dot" style="background:#66bb6a;"></span>LOW</span>
            <span class="legend-item"><span class="legend-dot" style="background:#78909c;"></span>INFO</span>
        </div>
    </section>

    <!-- Vulnerability Cards -->
    <section class="vulns-section">
        {final_rows_html}
    </section>
</main>

<footer class="report-footer">
    <div class="container">
        <p>Báo cáo được tạo tự động bởi <strong>WebSAST Automated Exploitation Framework (Mini DAST PoC)</strong></p>
        <p style="margin-top:4px;">Chỉ dùng cho mục đích nghiên cứu và kiểm thử hợp pháp.</p>
    </div>
</footer>

</body>
</html>"""
