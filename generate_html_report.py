#!/usr/bin/env python3
"""
Generate an interactive HTML report from IAM risk assessment data.
Usage: python3 generate_html_report.py <detailed_csv> [output.html]
"""

import csv
import sys
import json
from datetime import datetime
from pathlib import Path


def build_html(rows, generated_at, account_id=""):
    """Build a self-contained interactive HTML report.

    Args:
        rows: list of dicts with keys Username, Account_ID, Account_Name,
              Key_ID, Status, Created, Last_Used, Risk_Score, Risk_Factors,
              Managed_Policies, Inline_Policies, Console_Access, MFA_Enabled.
        generated_at: timestamp string for the report header.
        account_id: primary account ID shown in the header.
    """
    total = len(rows)
    active = sum(1 for r in rows if r.get("Status", "").upper() == "ACTIVE")
    inactive = total - active

    # Compute risk distribution
    critical = sum(1 for r in rows if int(r["Risk_Score"]) >= 7)
    high = sum(1 for r in rows if 5 <= int(r["Risk_Score"]) < 7)
    medium = sum(1 for r in rows if 3 <= int(r["Risk_Score"]) < 5)
    low = sum(1 for r in rows if int(r["Risk_Score"]) < 3)

    # Unique accounts
    accounts = {}
    for r in rows:
        aid = r.get("Account_ID", "")
        aname = r.get("Account_Name", "")
        if aid and aid not in accounts:
            accounts[aid] = aname

    num_accounts = len(accounts) or 1

    # Detect production/management accounts
    prod_keywords = ("production", "prod", "management", "mgmt")
    prod_accounts = set()
    for aid, aname in accounts.items():
        if any(kw in aname.lower() for kw in prod_keywords):
            prod_accounts.add(aid)

    critical_account_keys = sum(
        1 for r in rows if r.get("Account_ID", "") in prod_accounts
    )

    # Build account options for filter dropdown
    account_options = "".join(
        f'<option value="{aid}">{aid} ({aname})</option>'
        for aid, aname in sorted(accounts.items())
    )

    # Build unique score options
    scores = sorted(set(int(r["Risk_Score"]) for r in rows))
    score_options = "".join(
        f'<option value="{s}">{s}</option>' for s in scores
    )

    # Build JSON data array for JS
    js_data = []
    for r in rows:
        aid = r.get("Account_ID", "")
        js_data.append({
            "username": r.get("Username", ""),
            "account_id": aid,
            "account_name": r.get("Account_Name", ""),
            "key_id": r.get("Key_ID", ""),
            "status": r.get("Status", "").upper(),
            "created": r.get("Created", ""),
            "last_used": r.get("Last_Used", ""),
            "risk_score": int(r["Risk_Score"]),
            "risk_factors": r.get("Risk_Factors", ""),
            "managed_policies": r.get("Managed_Policies", ""),
            "inline_policies": r.get("Inline_Policies", ""),
            "console_access": r.get("Console_Access", "No"),
            "mfa_enabled": r.get("MFA_Enabled", "No"),
            "is_production": aid in prod_accounts,
        })

    data_json = json.dumps(js_data, ensure_ascii=False)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IAM Access Key Risk Assessment</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f7fa;color:#333;padding:20px}}
.container{{max-width:1400px;margin:0 auto}}
h1{{color:#1a252f;margin-bottom:5px}}
.generated{{color:#666;margin-bottom:20px;font-size:14px}}
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:15px;margin-bottom:25px}}
.stat-card{{background:#fff;border-radius:8px;padding:18px;box-shadow:0 1px 3px rgba(0,0,0,.1);text-align:center}}
.stat-card .value{{font-size:28px;font-weight:700}}
.stat-card .label{{font-size:13px;color:#666;margin-top:4px}}
.stat-card.critical .value{{color:#d32f2f}}
.stat-card.high .value{{color:#f57c00}}
.stat-card.medium .value{{color:#fbc02d}}
.stat-card.low .value{{color:#388e3c}}
.summary-section{{margin-bottom:25px}}
.stats-row{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:12px}}
.section-label{{font-size:12px;font-weight:600;color:#888;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}}
.global-search{{margin-bottom:15px}}
.global-search input{{padding:8px 12px;border:1px solid #ddd;border-radius:6px;font-size:14px;width:100%;max-width:500px}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
th{{background:#1a252f;color:#fff;padding:10px 12px;text-align:left;font-size:13px;cursor:pointer;white-space:nowrap}}
th:hover{{background:#2c3e50}}
th .sort-arrow{{font-size:10px;margin-left:4px}}
.col-filters td{{background:#e8ecf0;padding:6px 8px}}
.col-filters input,.col-filters select{{width:100%;padding:4px 6px;border:1px solid #ccc;border-radius:4px;font-size:12px}}
td{{padding:9px 12px;border-bottom:1px solid #eee;font-size:13px}}
tr:hover td{{background:#f0f4f8}}
.score{{display:inline-block;padding:2px 8px;border-radius:12px;font-weight:600;font-size:12px;color:#fff}}
.score-critical{{background:#d32f2f}}
.score-high{{background:#f57c00}}
.score-medium{{background:#fbc02d;color:#333}}
.score-low{{background:#388e3c}}
.pagination{{display:flex;justify-content:center;align-items:center;gap:8px;margin-top:15px}}
.pagination button{{padding:6px 14px;border:1px solid #ddd;border-radius:6px;background:#fff;cursor:pointer;font-size:13px}}
.pagination button:hover{{background:#e8ecf0}}
.pagination button:disabled{{opacity:.4;cursor:default}}
.pagination .info{{font-size:13px;color:#666}}
.risk-factors{{max-width:300px;font-size:12px}}
.clear-btn{{padding:6px 14px;border:1px solid #ddd;border-radius:6px;background:#fff;cursor:pointer;font-size:13px;margin-left:10px}}
.clear-btn:hover{{background:#e8ecf0}}
.prod-toggle{{display:inline-flex;align-items:center;gap:6px;margin-left:15px;font-size:13px;cursor:pointer}}
.prod-toggle input{{cursor:pointer}}
</style>
</head>
<body>
<div class="container">
<h1>IAM Access Key Risk Assessment</h1>
<p class="generated">Generated: {generated_at}</p>

<div class="summary-section">
  <div class="section-label">Overview</div>
  <div class="stats-row">
    <div class="stat-card"><div class="value">{num_accounts}</div><div class="label">AWS Accounts</div></div>
    <div class="stat-card"><div class="value">{total}</div><div class="label">Total Keys</div></div>
    <div class="stat-card"><div class="value">{active}</div><div class="label">Active Keys</div></div>
    <div class="stat-card"><div class="value">{inactive}</div><div class="label">Inactive Keys</div></div>
    <div class="stat-card critical"><div class="value">{critical_account_keys}</div><div class="label">Critical Account Keys</div></div>
  </div>
  <div class="section-label">Risk Distribution</div>
  <div class="stats-row">
    <div class="stat-card critical"><div class="value">{critical}</div><div class="label">Critical (7-10)</div></div>
    <div class="stat-card high"><div class="value">{high}</div><div class="label">High (5-6)</div></div>
    <div class="stat-card medium"><div class="value">{medium}</div><div class="label">Medium (3-4)</div></div>
    <div class="stat-card low"><div class="value">{low}</div><div class="label">Low (0-2)</div></div>
  </div>
</div>

<div class="global-search">
<input type="text" id="globalSearch" placeholder="Search across all columns..." oninput="applyFilters()">
<button class="clear-btn" onclick="clearAll()">Clear All Filters</button>
<label class="prod-toggle"><input type="checkbox" id="prodOnly" onchange="applyFilters()"> Critical Account Only</label>
</div>

<table>
<thead>
<tr>
  <th onclick="sortTable('username')">User <span class="sort-arrow" id="sort-username"></span></th>
  <th onclick="sortTable('account_name')">Account <span class="sort-arrow" id="sort-account_name"></span></th>
  <th onclick="sortTable('key_id')">Key ID <span class="sort-arrow" id="sort-key_id"></span></th>
  <th onclick="sortTable('status')">Status <span class="sort-arrow" id="sort-status"></span></th>
  <th onclick="sortTable('risk_score')">Score <span class="sort-arrow" id="sort-risk_score"></span></th>
  <th onclick="sortTable('created')">Created <span class="sort-arrow" id="sort-created"></span></th>
  <th onclick="sortTable('last_used')">Last Used <span class="sort-arrow" id="sort-last_used"></span></th>
  <th>Risk Factors</th>
  <th onclick="sortTable('console_access')">Console <span class="sort-arrow" id="sort-console_access"></span></th>
  <th onclick="sortTable('mfa_enabled')">MFA <span class="sort-arrow" id="sort-mfa_enabled"></span></th>
</tr>
<tr class="col-filters">
  <td><input type="text" id="f-username" placeholder="Filter..." oninput="applyFilters()"></td>
  <td><select id="f-account" onchange="applyFilters()"><option value="">All</option>{account_options}</select></td>
  <td><input type="text" id="f-key_id" placeholder="Filter..." oninput="applyFilters()"></td>
  <td><select id="f-status" onchange="applyFilters()"><option value="">All</option><option value="ACTIVE">Active</option><option value="INACTIVE">Inactive</option></select></td>
  <td><select id="f-score" onchange="applyFilters()"><option value="">All</option>{score_options}</select></td>
  <td><input type="text" id="f-created" placeholder="e.g. 2024-04" oninput="applyFilters()"></td>
  <td><input type="text" id="f-last_used" placeholder="e.g. 2025" oninput="applyFilters()"></td>
  <td><input type="text" id="f-risk_factors" placeholder="Filter..." oninput="applyFilters()"></td>
  <td><select id="f-console" onchange="applyFilters()"><option value="">All</option><option value="Yes">Yes</option><option value="No">No</option></select></td>
  <td><select id="f-mfa" onchange="applyFilters()"><option value="">All</option><option value="Yes">Yes</option><option value="No">No</option></select></td>
</tr>
</thead>
<tbody id="tableBody"></tbody>
</table>

<div class="pagination">
<button onclick="changePage(-1)" id="prevBtn">&larr; Prev</button>
<span class="info" id="pageInfo"></span>
<button onclick="changePage(1)" id="nextBtn">Next &rarr;</button>
</div>
</div>

<script>
const DATA={data_json};
let filtered=[...DATA];
let currentPage=1;
const perPage=25;
let sortKey='risk_score';
let sortAsc=false;

function scoreClass(s){{if(s>=7)return'score-critical';if(s>=5)return'score-high';if(s>=3)return'score-medium';return'score-low'}}

function updateSortArrows(){{
  document.querySelectorAll('.sort-arrow').forEach(el=>el.textContent='');
  const el=document.getElementById('sort-'+sortKey);
  if(el)el.textContent=sortAsc?'\\u25B2':'\\u25BC';
}}

function renderTable(){{
  const start=(currentPage-1)*perPage;
  const page=filtered.slice(start,start+perPage);
  const tbody=document.getElementById('tableBody');
  tbody.innerHTML=page.map(r=>`<tr>
<td>${{r.username}}</td>
<td>${{r.account_id}}<br><small>${{r.account_name}}</small></td>
<td><code>${{r.key_id}}</code></td>
<td>${{r.status}}</td>
<td><span class="score ${{scoreClass(r.risk_score)}}">${{r.risk_score}}</span></td>
<td>${{r.created}}</td>
<td>${{r.last_used}}</td>
<td class="risk-factors">${{r.risk_factors||'\\u2014'}}</td>
<td>${{r.console_access}}</td>
<td>${{r.mfa_enabled}}</td>
  </tr>`).join('');
  const totalPages=Math.ceil(filtered.length/perPage)||1;
  document.getElementById('pageInfo').textContent=`Page ${{currentPage}} of ${{totalPages}} (${{filtered.length}} results)`;
  document.getElementById('prevBtn').disabled=currentPage<=1;
  document.getElementById('nextBtn').disabled=currentPage>=totalPages;
  updateSortArrows();
}}

function applyFilters(){{
  const g=document.getElementById('globalSearch').value.toLowerCase();
  const fUser=document.getElementById('f-username').value.toLowerCase();
  const fAcc=document.getElementById('f-account').value;
  const fKey=document.getElementById('f-key_id').value.toLowerCase();
  const fStatus=document.getElementById('f-status').value;
  const fScore=document.getElementById('f-score').value;
  const fCreated=document.getElementById('f-created').value.toLowerCase();
  const fLastUsed=document.getElementById('f-last_used').value.toLowerCase();
  const fRisk=document.getElementById('f-risk_factors').value.toLowerCase();
  const fConsole=document.getElementById('f-console').value;
  const fMfa=document.getElementById('f-mfa').value;
  const prodOnly=document.getElementById('prodOnly').checked;

  filtered=DATA.filter(r=>{{
    if(prodOnly&&!r.is_production)return false;
    if(g){{const all=Object.values(r).join(' ').toLowerCase();if(!all.includes(g))return false}}
    if(fUser&&!r.username.toLowerCase().includes(fUser))return false;
    if(fAcc&&r.account_id!==fAcc)return false;
    if(fKey&&!r.key_id.toLowerCase().includes(fKey))return false;
    if(fStatus&&r.status!==fStatus)return false;
    if(fScore&&r.risk_score!==parseInt(fScore))return false;
    if(fCreated&&!r.created.toLowerCase().includes(fCreated))return false;
    if(fLastUsed&&!r.last_used.toLowerCase().includes(fLastUsed))return false;
    if(fRisk&&!r.risk_factors.toLowerCase().includes(fRisk))return false;
    if(fConsole&&r.console_access!==fConsole)return false;
    if(fMfa&&r.mfa_enabled!==fMfa)return false;
    return true;
  }});
  doSort();
  currentPage=1;
  renderTable();
}}

function clearAll(){{
  document.getElementById('globalSearch').value='';
  document.getElementById('prodOnly').checked=false;
  document.querySelectorAll('.col-filters input').forEach(el=>el.value='');
  document.querySelectorAll('.col-filters select').forEach(el=>el.value='');
  applyFilters();
}}

function sortTable(key){{
  if(sortKey===key)sortAsc=!sortAsc;
  else{{sortKey=key;sortAsc=true}}
  doSort();
  renderTable();
}}

function doSort(){{
  filtered.sort((a,b)=>{{
    let va=a[sortKey],vb=b[sortKey];
    if(typeof va==='number')return sortAsc?va-vb:vb-va;
    va=String(va).toLowerCase();vb=String(vb).toLowerCase();
    return sortAsc?va.localeCompare(vb):vb.localeCompare(va);
  }});
}}

function changePage(delta){{currentPage+=delta;renderTable()}}

doSort();
renderTable();
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

    account_id = rows[0].get("Account_ID", "") if rows else ""
    html = build_html(rows, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), account_id)

    with open(out_path, "w") as f:
        f.write(html)

    print(f"✅ HTML report saved to: {out_path}")


if __name__ == "__main__":
    main()
