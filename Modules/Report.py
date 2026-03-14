import json
import os
from datetime import datetime


class Report:
    def __init__(self, json_file="Json/result.json", report_dir="Report"):
        self.json_file  = json_file
        self.report_dir = report_dir
        self.data       = []

        # Load the scan results that BannerScanner produced
        try:
            with open(self.json_file, "r") as f:
                self.data = json.load(f)
            print(f"Loaded {len(self.data)} host(s) from {self.json_file}")
        except FileNotFoundError:
            print(f"Error: '{self.json_file}' not found. Run a scan first.")
        except json.JSONDecodeError:
            print(f"Error: '{self.json_file}' contains invalid JSON.")

    # ─────────────────────────────────────────────
    #  Helpers
    # ─────────────────────────────────────────────

    def _risk_level(self, port, service, banner):
        # Flag ports that are commonly exposed or unencrypted
        high_risk_ports   = {21, 23, 445, 3389, 5900, 5901, 5902, 27017, 6379, 11211, 2375}
        medium_risk_ports = {22, 25, 80, 110, 143, 3306, 5432, 1433, 8080, 8443, 9200}
        if port in high_risk_ports:   return "HIGH"
        if port in medium_risk_ports: return "MEDIUM"
        return "LOW"

    def _risk_badge(self, level):
        return {"HIGH": "[!!!]", "MEDIUM": "[!] ", "LOW": "[ ] "}.get(level, "[ ] ")

    def _banner_preview(self, banner, max_len=80):
        # Collapse whitespace and trim to keep the report readable
        if not banner or banner in ("No Banner", "Timeout") or banner.startswith(("Connection Failed", "Error")):
            return banner or "—"
        cleaned = banner.replace("\r\n", " | ").replace("\r", " ").replace("\n", " ")
        return cleaned[:max_len] + ("…" if len(cleaned) > max_len else "")

    def _count_stats(self):
        total_ports = 0
        services    = {}
        oses        = {}
        risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for host in self.data:
            for p in host.get("Ports", []):
                total_ports += 1
                svc  = p.get("Service", "Unknown")
                os_  = p.get("OS",      "Unknown")
                risk = self._risk_level(p["Port"], svc, p.get("Banner", ""))
                services[svc]    = services.get(svc, 0) + 1
                oses[os_]        = oses.get(os_, 0)     + 1
                risk_counts[risk] += 1

        return total_ports, services, oses, risk_counts

    # ─────────────────────────────────────────────
    #  Text Report
    # ─────────────────────────────────────────────

    def _build_text_report(self):
        now         = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        total_hosts = len(self.data)
        total_ports, services, oses, risks = self._count_stats()

        lines = []
        div  = "=" * 72
        thin = "-" * 72

        lines += [
            div,
            "  NETWORK SCAN REPORT",
            f"  Generated : {now}",
            f"  Hosts     : {total_hosts}",
            f"  Open Ports: {total_ports}",
            div, "",
        ]

        lines += ["  RISK SUMMARY", thin,
            f"  {self._risk_badge('HIGH')}  HIGH   : {risks['HIGH']} port(s)  — unencrypted / commonly exploited",
            f"  {self._risk_badge('MEDIUM')}  MEDIUM : {risks['MEDIUM']} port(s)  — worth reviewing",
            f"  {self._risk_badge('LOW')}  LOW    : {risks['LOW']} port(s)  — generally safe", "",
        ]

        lines += ["  SERVICES FOUND", thin]
        for svc, count in sorted(services.items(), key=lambda x: -x[1]):
            lines.append(f"  {svc.ljust(20)} {count} port(s)")
        lines.append("")

        lines += ["  DETECTED OPERATING SYSTEMS", thin]
        for os_, count in sorted(oses.items(), key=lambda x: -x[1]):
            lines.append(f"  {os_.ljust(20)} {count} port(s)")
        lines.append("")

        lines += [div, "  HOST DETAILS", div]
        for host in sorted(self.data, key=lambda x: x.get("IP Address", "")):
            ip    = host.get("IP Address", "N/A")
            ports = host.get("Ports", [])
            lines += ["", f"  Host: {ip}", f"  Open ports: {len(ports)}", thin,
                f"  {'PORT':<8} {'RISK':<8} {'SERVICE':<18} {'OS':<16} BANNER PREVIEW", thin]
            for p in sorted(ports, key=lambda x: x["Port"]):
                port    = p["Port"]
                service = p.get("Service", "Unknown")
                os_info = p.get("OS",      "Unknown")
                banner  = self._banner_preview(p.get("Banner", ""))
                risk    = self._risk_level(port, service, p.get("Banner", ""))
                lines.append(f"  {str(port):<8} {self._risk_badge(risk):<8} {service:<18} {os_info:<16} {banner}")

        lines += ["", div, "  END OF REPORT", div]
        return "\n".join(lines)

    # ─────────────────────────────────────────────
    #  HTML Report  (white + orange theme)
    # ─────────────────────────────────────────────

    def _build_html_report(self):
        now         = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_hosts = len(self.data)
        total_ports, services, oses, risks = self._count_stats()

        risk_color = {"HIGH": "#e53e3e", "MEDIUM": "#dd6b20", "LOW": "#2f855a"}
        risk_bg    = {"HIGH": "#fff5f5", "MEDIUM": "#fffaf0", "LOW": "#f0fff4"}

        # ── Summary stat cards ───────────────────────────────────────────────
        stat_cards = f"""
        <div class="stat-card accent">
          <div class="stat-num">{total_hosts}</div>
          <div class="stat-lbl">Hosts Scanned</div>
        </div>
        <div class="stat-card">
          <div class="stat-num">{total_ports}</div>
          <div class="stat-lbl">Open Ports</div>
        </div>
        <div class="stat-card high">
          <div class="stat-num">{risks['HIGH']}</div>
          <div class="stat-lbl">High Risk</div>
        </div>
        <div class="stat-card medium">
          <div class="stat-num">{risks['MEDIUM']}</div>
          <div class="stat-lbl">Medium Risk</div>
        </div>
        <div class="stat-card low">
          <div class="stat-num">{risks['LOW']}</div>
          <div class="stat-lbl">Low Risk</div>
        </div>"""

        # ── Services table ───────────────────────────────────────────────────
        svc_rows = ""
        for rank, (svc, count) in enumerate(sorted(services.items(), key=lambda x: -x[1]), 1):
            bar_pct = int(count / total_ports * 100) if total_ports else 0
            svc_rows += f"""
            <tr>
              <td class="rank">#{rank}</td>
              <td><strong>{svc}</strong></td>
              <td>{count}</td>
              <td>
                <div class="bar-wrap">
                  <div class="bar-fill" style="width:{bar_pct}%"></div>
                </div>
              </td>
            </tr>"""

        # ── OS table ────────────────────────────────────────────────────────
        os_rows = ""
        for os_, count in sorted(oses.items(), key=lambda x: -x[1]):
            bar_pct = int(count / total_ports * 100) if total_ports else 0
            os_rows += f"""
            <tr>
              <td><strong>{os_}</strong></td>
              <td>{count}</td>
              <td>
                <div class="bar-wrap">
                  <div class="bar-fill" style="width:{bar_pct}%"></div>
                </div>
              </td>
            </tr>"""

        # ── Risk distribution table ──────────────────────────────────────────
        risk_rows = ""
        for level in ["HIGH", "MEDIUM", "LOW"]:
            count   = risks[level]
            bar_pct = int(count / total_ports * 100) if total_ports else 0
            color   = risk_color[level]
            risk_rows += f"""
            <tr>
              <td><span class="risk-badge" style="color:{color};background:{risk_bg[level]}">{level}</span></td>
              <td>{count}</td>
              <td>
                <div class="bar-wrap">
                  <div class="bar-fill" style="width:{bar_pct}%;background:{color}"></div>
                </div>
              </td>
            </tr>"""

        # ── Host detail cards ────────────────────────────────────────────────
        host_cards = ""
        for host in sorted(self.data, key=lambda x: x.get("IP Address", "")):
            ip    = host.get("IP Address", "N/A")
            ports = host.get("Ports", [])

            port_rows = ""
            for p in sorted(ports, key=lambda x: x["Port"]):
                port    = p["Port"]
                service = p.get("Service", "Unknown")
                os_info = p.get("OS",      "Unknown")
                banner  = self._banner_preview(p.get("Banner", ""), max_len=100)
                risk    = self._risk_level(port, service, p.get("Banner", ""))
                color   = risk_color[risk]
                bg      = risk_bg[risk]

                port_rows += f"""
                <tr>
                  <td class="port-num">{port}</td>
                  <td><span class="risk-badge" style="color:{color};background:{bg}">{risk}</span></td>
                  <td>{service}</td>
                  <td>{os_info}</td>
                  <td class="banner-cell">{banner}</td>
                </tr>"""

            host_cards += f"""
            <div class="host-card">
              <div class="host-header">
                <span class="host-ip">&#9670; {ip}</span>
                <span class="host-tag">{len(ports)} open port(s)</span>
              </div>
              <table class="port-table">
                <thead>
                  <tr>
                    <th>Port</th>
                    <th>Risk</th>
                    <th>Service</th>
                    <th>OS</th>
                    <th>Banner Preview</th>
                  </tr>
                </thead>
                <tbody>{port_rows}</tbody>
              </table>
            </div>"""

        # ── Full HTML ────────────────────────────────────────────────────────
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>ViperScan Report — {now}</title>
  <style>
    /* ── Reset & base ── */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', Arial, sans-serif;
      background: #f7f7f7;
      color: #1a1a1a;
      min-height: 100vh;
    }}

    /* ── Top header bar ── */
    .top-bar {{
      background: linear-gradient(135deg, #e8630a 0%, #c94f00 100%);
      color: white;
      padding: 28px 40px 22px;
      border-bottom: 4px solid #a33f00;
    }}
    .top-bar h1 {{
      font-size: 1.75rem;
      font-weight: 700;
      letter-spacing: -0.5px;
    }}
    .top-bar h1 span {{ opacity: 0.75; font-weight: 400; }}
    .top-bar .meta {{
      margin-top: 6px;
      font-size: 0.83rem;
      opacity: 0.85;
    }}

    /* ── Page wrapper ── */
    .page {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px 60px; }}

    /* ── Section heading ── */
    .section-title {{
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1.5px;
      color: #e8630a;
      margin: 36px 0 12px;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .section-title::after {{
      content: "";
      flex: 1;
      height: 1px;
      background: #e8630a44;
    }}

    /* ── Stat cards row ── */
    .stat-row {{
      display: flex;
      gap: 14px;
      flex-wrap: wrap;
      margin-bottom: 8px;
    }}
    .stat-card {{
      background: white;
      border: 1px solid #e2e2e2;
      border-top: 4px solid #ccc;
      border-radius: 8px;
      padding: 18px 24px;
      min-width: 130px;
      flex: 1;
      text-align: center;
      box-shadow: 0 1px 4px rgba(0,0,0,.06);
    }}
    .stat-card.accent {{ border-top-color: #e8630a; }}
    .stat-card.high    {{ border-top-color: #e53e3e; }}
    .stat-card.medium  {{ border-top-color: #dd6b20; }}
    .stat-card.low     {{ border-top-color: #2f855a; }}
    .stat-num {{
      font-size: 2.2rem;
      font-weight: 800;
      color: #1a1a1a;
      line-height: 1;
    }}
    .stat-card.accent .stat-num {{ color: #e8630a; }}
    .stat-card.high    .stat-num {{ color: #e53e3e; }}
    .stat-card.medium  .stat-num {{ color: #dd6b20; }}
    .stat-card.low     .stat-num {{ color: #2f855a; }}
    .stat-lbl {{
      font-size: 0.78rem;
      color: #777;
      margin-top: 5px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}

    /* ── Summary tables grid ── */
    .summary-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr 1fr;
      gap: 18px;
      margin-bottom: 8px;
    }}
    @media (max-width: 720px) {{
      .summary-grid {{ grid-template-columns: 1fr; }}
    }}

    /* ── Generic table card ── */
    .tbl-card {{
      background: white;
      border: 1px solid #e2e2e2;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 1px 4px rgba(0,0,0,.06);
    }}
    .tbl-card-title {{
      background: #fff4ec;
      border-bottom: 1px solid #f0d5c0;
      padding: 10px 16px;
      font-size: 0.78rem;
      font-weight: 700;
      color: #c94f00;
      text-transform: uppercase;
      letter-spacing: 1px;
    }}
    .tbl-card table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.84rem;
    }}
    .tbl-card th {{
      background: #fafafa;
      border-bottom: 1px solid #eee;
      padding: 8px 14px;
      text-align: left;
      font-size: 0.72rem;
      color: #999;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .tbl-card td {{
      padding: 8px 14px;
      border-bottom: 1px solid #f3f3f3;
      vertical-align: middle;
    }}
    .tbl-card tr:last-child td {{ border-bottom: none; }}
    .tbl-card tr:hover td {{ background: #fff8f3; }}
    .rank {{ color: #bbb; font-size: 0.75rem; width: 28px; }}

    /* ── Mini bar chart ── */
    .bar-wrap {{
      background: #f0f0f0;
      border-radius: 4px;
      height: 8px;
      overflow: hidden;
      min-width: 80px;
    }}
    .bar-fill {{
      height: 100%;
      background: #e8630a;
      border-radius: 4px;
      transition: width 0.3s;
    }}

    /* ── Risk badge ── */
    .risk-badge {{
      display: inline-block;
      padding: 2px 9px;
      border-radius: 20px;
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: 0.5px;
    }}

    /* ── Host cards ── */
    .host-card {{
      background: white;
      border: 1px solid #e2e2e2;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 1px 4px rgba(0,0,0,.06);
      margin-bottom: 18px;
    }}
    .host-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 13px 18px;
      background: linear-gradient(90deg, #fff4ec, #fff);
      border-bottom: 2px solid #e8630a;
    }}
    .host-ip {{
      font-size: 1rem;
      font-weight: 700;
      color: #c94f00;
    }}
    .host-tag {{
      font-size: 0.78rem;
      color: white;
      background: #e8630a;
      border-radius: 20px;
      padding: 3px 12px;
      font-weight: 600;
    }}

    /* ── Port detail table ── */
    .port-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.84rem;
    }}
    .port-table th {{
      background: #fafafa;
      padding: 8px 14px;
      text-align: left;
      font-size: 0.72rem;
      color: #999;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border-bottom: 1px solid #eee;
    }}
    .port-table td {{
      padding: 9px 14px;
      border-bottom: 1px solid #f3f3f3;
      vertical-align: top;
    }}
    .port-table tr:last-child td {{ border-bottom: none; }}
    .port-table tr:hover td {{ background: #fff8f3; }}
    .port-num {{
      font-weight: 700;
      color: #e8630a;
      white-space: nowrap;
    }}
    .banner-cell {{
      font-family: monospace;
      font-size: 0.77rem;
      color: #666;
      word-break: break-all;
    }}

    /* ── Footer ── */
    .footer {{
      text-align: center;
      color: #bbb;
      font-size: 0.78rem;
      margin-top: 48px;
      padding-top: 20px;
      border-top: 1px solid #eee;
    }}
  </style>
</head>
<body>

  <!-- Header -->
  <div class="top-bar">
    <h1>&#128013; ViperScan <span>/ Scan Report</span></h1>
    <div class="meta">ViperScan &nbsp;&bull;&nbsp; Generated on {now} &nbsp;&bull;&nbsp; {total_hosts} host(s) &nbsp;&bull;&nbsp; {total_ports} open port(s)</div>
  </div>

  <div class="page">

    <!-- Stat cards -->
    <div class="section-title">Overview</div>
    <div class="stat-row">
      {stat_cards}
    </div>

    <!-- Summary tables: Services / OS / Risk -->
    <div class="section-title">Summary Tables</div>
    <div class="summary-grid">

      <!-- Services -->
      <div class="tbl-card">
        <div class="tbl-card-title">&#127959; Services Found</div>
        <table>
          <thead><tr><th>#</th><th>Service</th><th>Ports</th><th>Share</th></tr></thead>
          <tbody>{svc_rows}</tbody>
        </table>
      </div>

      <!-- OS -->
      <div class="tbl-card">
        <div class="tbl-card-title">&#128187; Operating Systems</div>
        <table>
          <thead><tr><th>OS</th><th>Ports</th><th>Share</th></tr></thead>
          <tbody>{os_rows}</tbody>
        </table>
      </div>

      <!-- Risk -->
      <div class="tbl-card">
        <div class="tbl-card-title">&#9888; Risk Distribution</div>
        <table>
          <thead><tr><th>Level</th><th>Ports</th><th>Share</th></tr></thead>
          <tbody>{risk_rows}</tbody>
        </table>
      </div>

    </div>

    <!-- Per-host details -->
    <div class="section-title">Host Details</div>
    {host_cards}

    <div class="footer">
      ViperScan &mdash; Network Scan Report &mdash; {now}
    </div>

  </div>
</body>
</html>"""
        return html

    # ─────────────────────────────────────────────
    #  Public entry point
    # ─────────────────────────────────────────────

    def generate(self):
        if not self.data:
            print("No data to report. Did the scan find anything?")
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        txt_path = os.path.join(self.report_dir, f"report_{ts}.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(self._build_text_report())
        print(f"  Text report  → {txt_path}")

        html_path = os.path.join(self.report_dir, f"report_{ts}.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(self._build_html_report())
        print(f"  HTML report  → {html_path}")