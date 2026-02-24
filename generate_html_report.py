#!/usr/bin/env python3
"""
Generate a rich HTML report from IAM risk assessment CSV output.
Usage: python3 generate_html_report.py <detailed_csv> [output.html]
"""

import csv
import sys
import json
from datetime import datetime
from pathlib import Path


def score_class(score):
    s = int(score)
    if s >= 8: return "critical"
    if s >= 5: return "high"
    if s >= 3: return "medium"
    if s >= 1: return "low"
    return "none"

def score_label(score):
    s = int(score)
    if s >= 8: return "CRITICAL"
    if s >= 5: return "HIGH"
    if s >= 3: return "MEDIUM"
    if s >= 1: return "LOW"
    return "NONE"

def render_badge(val, true_is_good=False):
    if val in ("Yes", "True", "true", "yes"):
        cls = "badge-good" if true_is_good else "badge-bad"
        icon = "✓"
        return f'<span class="badge {cls}">{icon} Yes</span>'
    if val in ("No", "False", "false", "no"):
        cls = "badge-bad" if true_is_good else "badge-good"
        icon = "✗"
        return f'<span class="badge {cls}">{icon} No</span>'
    return f'<span class="badge badge-neutral">{val}</span>'

def build_html(rows, generated_at):
    total = len(rows)
    active = sum(1 for r in rows if r["Status"] == "Active")
    inactive = total - active
    critical = sum(1 for r in rows if int(r["Risk_Score"]) >= 8)
    high     = sum(1 for r in rows if 5 <= int(r["Risk_Score"]) < 8)
    medium   = sum(1 for r in rows if 3 <= int(r["Risk_Score"]) < 5)
    low      = sum(1 for r in rows if 1 <= int(r["Risk_Score"]) < 3)
    no_mfa   = sum(1 for r in rows if r["MFA_Enabled"] == "No" and r["Status"] == "Active")
    has_mfa  = sum(1 for r in rows if r["MFA_Enabled"] == "Yes" and r["Status"] == "Active")
    console  = sum(1 for r in rows if r["Console_Access"] == "Yes")

    rows_sorted = sorted(rows, key=lambda r: int(r["Risk_Score"]), reverse=True)

    # Per-user chart data (highest score per user)
    user_scores = {}
    for r in rows_sorted:
        u = r["Username"]
        s = int(r["Risk_Score"])
        if u not in user_scores or s > user_scores[u]:
            user_scores[u] = s
    user_labels = json.dumps(list(user_scores.keys()))
    user_data   = json.dumps(list(user_scores.values()))
    user_colors = json.dumps([
        "#e53e3e" if s >= 8 else "#dd6b20" if s >= 5 else "#d69e2e" if s >= 3 else "#38a169"
        for s in user_scores.values()
    ])

    def key_rows():
        out = []
        for r in rows_sorted:
            sc = int(r["Risk_Score"])
            cls = score_class(sc)
            label = score_label(sc)
            factors = "".join(
                f'<li>{f.strip()}</li>'
                for f in r["Risk_Factors"].split(";") if f.strip()
            )
            policies = " · ".join(p.strip() for p in r["Managed_Policies"].split(";") if p.strip())
            inline = r.get("Inline_Policies", "").strip() or "—"
            last_used = r["Last_Used"][:10] if r.get("Last_Used") else "—"
            out.append(f"""
            <tr class="row-{cls}">
              <td><strong>{r['Username']}</strong></td>
              <td class="mono">{r['Key_ID']}</td>
              <td>{render_badge(r['Status'])}</td>
              <td>{r['Created'][:10]}</td>
              <td>{last_used}</td>
              <td>
                <div class="score-wrap">
                  <span class="score-num score-{cls}">{sc}</span>
                  <span class="score-bar-bg"><span class="score-bar score-bar-{cls}" style="width:{sc*10}%"></span></span>
                  <span class="score-lbl score-{cls}">{label}</span>
                </div>
              </td>
              <td>{render_badge(r['MFA_Enabled'], true_is_good=True)}</td>
              <td>{render_badge(r['Console_Access'])}</td>
              <td class="factors"><ul>{factors}</ul></td>
              <td class="policies">{policies}<br><em class="inline-pol">{inline}</em></td>
            </tr>""")
        return "\n".join(out)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS IAM Key Risk Assessment</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: #f0f2f5; color: #1a202c; min-height: 100vh; }}

  /* ── Header ── */
  header {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
            color: white; padding: 2rem 2.5rem; display: flex; align-items: center; gap: 1rem; }}
  header .icon {{ font-size: 2.2rem; }}
  header h1 {{ font-size: 1.5rem; font-weight: 700; }}
  header p {{ opacity: 0.6; font-size: 0.82rem; margin-top: 0.25rem; }}

  /* ── Summary cards ── */
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
              gap: 1rem; padding: 1.5rem 2.5rem; }}
  .card {{ background: white; border-radius: 12px; padding: 1.2rem 1.4rem;
           box-shadow: 0 1px 4px rgba(0,0,0,0.07); border-top: 4px solid #e2e8f0;
           transition: transform .15s; }}
  .card:hover {{ transform: translateY(-2px); }}
  .card.c-critical {{ border-color: #e53e3e; }}
  .card.c-high     {{ border-color: #dd6b20; }}
  .card.c-medium   {{ border-color: #d69e2e; }}
  .card.c-blue     {{ border-color: #3182ce; }}
  .card.c-green    {{ border-color: #38a169; }}
  .card .num {{ font-size: 2.2rem; font-weight: 800; line-height: 1; }}
  .card .lbl {{ font-size: 0.7rem; color: #718096; margin-top: 0.3rem;
                text-transform: uppercase; letter-spacing: 0.06em; }}
  .card.c-critical .num {{ color: #e53e3e; }}
  .card.c-high     .num {{ color: #dd6b20; }}
  .card.c-medium   .num {{ color: #d69e2e; }}
  .card.c-blue     .num {{ color: #3182ce; }}
  .card.c-green    .num {{ color: #38a169; }}

  /* ── Charts row ── */
  .charts {{ display: grid; grid-template-columns: 260px 1fr 260px;
             gap: 1rem; padding: 0 2.5rem 1.5rem; align-items: start; }}
  .chart-box {{ background: white; border-radius: 12px; padding: 1.2rem;
                box-shadow: 0 1px 4px rgba(0,0,0,0.07); }}
  .chart-box h3 {{ font-size: 0.78rem; font-weight: 700; text-transform: uppercase;
                   letter-spacing: 0.06em; color: #718096; margin-bottom: 1rem; }}
  .chart-box canvas {{ max-height: 220px; }}

  /* ── Table ── */
  .table-wrap {{ padding: 0 2.5rem 2.5rem; overflow-x: auto; }}
  .section-title {{ font-size: 0.78rem; font-weight: 700; text-transform: uppercase;
                    letter-spacing: 0.06em; color: #718096; margin-bottom: 0.75rem; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 12px;
           box-shadow: 0 1px 4px rgba(0,0,0,0.07); overflow: hidden; font-size: 0.82rem; }}
  thead tr {{ background: #0f172a; color: white; }}
  thead th {{ padding: 0.8rem 0.9rem; text-align: left; font-size: 0.72rem;
              text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap; }}
  tbody tr {{ border-bottom: 1px solid #f0f2f5; transition: background .1s; }}
  tbody tr:last-child {{ border-bottom: none; }}
  tbody tr:hover {{ filter: brightness(0.97); }}
  tbody td {{ padding: 0.75rem 0.9rem; vertical-align: top; }}
  tr.row-critical {{ background: #fff5f5; }}
  tr.row-high     {{ background: #fffaf0; }}
  tr.row-medium   {{ background: #fffff0; }}

  /* ── Score bar ── */
  .score-wrap {{ display: flex; align-items: center; gap: 0.4rem; min-width: 150px; }}
  .score-num {{ font-weight: 800; font-size: 1.1rem; min-width: 1.5rem; }}
  .score-bar-bg {{ flex: 1; background: #e2e8f0; border-radius: 999px; height: 6px; overflow: hidden; }}
  .score-bar {{ height: 100%; border-radius: 999px; }}
  .score-lbl {{ font-size: 0.65rem; font-weight: 700; min-width: 52px; }}
  .score-critical, .score-bar-critical {{ color: #e53e3e; background: #e53e3e; }}
  .score-high,     .score-bar-high     {{ color: #dd6b20; background: #dd6b20; }}
  .score-medium,   .score-bar-medium   {{ color: #d69e2e; background: #d69e2e; }}
  .score-low,      .score-bar-low      {{ color: #38a169; background: #38a169; }}
  .score-none,     .score-bar-none     {{ color: #a0aec0; background: #a0aec0; }}

  /* ── Badges ── */
  .badge {{ display: inline-block; padding: 0.2rem 0.55rem; border-radius: 999px;
            font-size: 0.7rem; font-weight: 700; }}
  .badge-bad     {{ background: #fed7d7; color: #c53030; }}
  .badge-good    {{ background: #c6f6d5; color: #276749; }}
  .badge-neutral {{ background: #e2e8f0; color: #4a5568; }}

  /* ── Misc ── */
  .mono {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.75rem; color: #4a5568; }}
  .factors ul {{ list-style: none; }}
  .factors li {{ padding: 0.08rem 0; color: #555; }}
  .factors li::before {{ content: "· "; color: #cbd5e0; }}
  .policies {{ color: #555; font-size: 0.76rem; max-width: 180px; line-height: 1.5; }}
  .inline-pol {{ color: #a0aec0; font-style: italic; }}
  footer {{ text-align: center; padding: 1.5rem; color: #a0aec0; font-size: 0.75rem; }}
</style>
</head>
<body>

<header>
  <div class="icon">🔐</div>
  <div>
    <h1>AWS IAM Access Key Risk Assessment</h1>
    <p>Account: 566801649110 &nbsp;·&nbsp; Generated: {generated_at}</p>
  </div>
</header>

<div class="summary">
  <div class="card c-blue">    <div class="num">{total}</div>   <div class="lbl">Total Keys</div></div>
  <div class="card c-blue">    <div class="num">{active}</div>  <div class="lbl">Active</div></div>
  <div class="card c-critical"><div class="num">{critical}</div><div class="lbl">Critical (8-10)</div></div>
  <div class="card c-high">    <div class="num">{high}</div>    <div class="lbl">High (5-7)</div></div>
  <div class="card c-medium">  <div class="num">{medium}</div>  <div class="lbl">Medium (3-4)</div></div>
  <div class="card c-critical"><div class="num">{no_mfa}</div>  <div class="lbl">No MFA</div></div>
  <div class="card c-green">   <div class="num">{has_mfa}</div> <div class="lbl">MFA Enabled</div></div>
</div>

<div class="charts">
  <div class="chart-box">
    <h3>Risk Distribution</h3>
    <canvas id="donutChart"></canvas>
  </div>
  <div class="chart-box">
    <h3>Risk Score per User</h3>
    <canvas id="barChart"></canvas>
  </div>
  <div class="chart-box">
    <h3>MFA Status (Active Keys)</h3>
    <canvas id="mfaChart"></canvas>
  </div>
</div>

<div class="table-wrap">
  <div class="section-title">All Access Keys — sorted by risk score</div>
  <table>
    <thead>
      <tr>
        <th>User</th>
        <th>Key ID</th>
        <th>Status</th>
        <th>Created</th>
        <th>Last Used</th>
        <th>Risk Score</th>
        <th>MFA</th>
        <th>Console</th>
        <th>Risk Factors</th>
        <th>Policies</th>
      </tr>
    </thead>
    <tbody>
      {key_rows()}
    </tbody>
  </table>
</div>

<footer>Generated by aws-iam-key-audit skill &nbsp;·&nbsp; {generated_at}</footer>

<script>
Chart.defaults.font.family = "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif";
Chart.defaults.font.size = 12;

// Donut — risk distribution
new Chart(document.getElementById('donutChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['Critical (8-10)', 'High (5-7)', 'Medium (3-4)', 'Low (1-2)', 'None'],
    datasets: [{{
      data: [{critical}, {high}, {medium}, {low}, {total - critical - high - medium - low}],
      backgroundColor: ['#e53e3e','#dd6b20','#d69e2e','#38a169','#a0aec0'],
      borderWidth: 2, borderColor: '#fff'
    }}]
  }},
  options: {{
    cutout: '68%',
    plugins: {{ legend: {{ position: 'bottom', labels: {{ boxWidth: 12, padding: 10, font: {{ size: 11 }} }} }} }}
  }}
}});

// Bar — score per user
new Chart(document.getElementById('barChart'), {{
  type: 'bar',
  data: {{
    labels: {user_labels},
    datasets: [{{
      label: 'Max Risk Score',
      data: {user_data},
      backgroundColor: {user_colors},
      borderRadius: 6, borderSkipped: false
    }}]
  }},
  options: {{
    indexAxis: 'y',
    scales: {{
      x: {{ min: 0, max: 10, grid: {{ color: '#f0f2f5' }}, ticks: {{ stepSize: 2 }} }},
      y: {{ grid: {{ display: false }} }}
    }},
    plugins: {{
      legend: {{ display: false }},
      tooltip: {{ callbacks: {{ label: ctx => ` Score: ${{ctx.parsed.x}}/10` }} }}
    }}
  }}
}});

// Donut — MFA status
new Chart(document.getElementById('mfaChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['No MFA ⚠️', 'MFA Enabled ✓'],
    datasets: [{{
      data: [{no_mfa}, {has_mfa}],
      backgroundColor: ['#e53e3e', '#38a169'],
      borderWidth: 2, borderColor: '#fff'
    }}]
  }},
  options: {{
    cutout: '68%',
    plugins: {{ legend: {{ position: 'bottom', labels: {{ boxWidth: 12, padding: 10, font: {{ size: 11 }} }} }} }}
  }}
}});
</script>
</body>
</html>"""


def main():
    if len(sys.argv) < 2:
        print("Usage: generate_html_report.py <detailed_csv> [output.html]")
        sys.exit(1)

    csv_path = Path(sys.argv[1])
    if not csv_path.exists():
        print(f"File not found: {csv_path}")
        sys.exit(1)

    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else csv_path.parent / "iam_risk_report.html"

    with open(csv_path, newline="") as f:
        rows = list(csv.DictReader(f))

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = build_html(rows, generated_at)

    with open(out_path, "w") as f:
        f.write(html)

    print(f"✅ HTML report saved to: {out_path}")


if __name__ == "__main__":
    main()
