<div align="center">

# 🔐 AWS IAM Access Keys Risk Assessment Tool

### *Identify, Assess, and Remediate IAM Security Risks*

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![AWS](https://img.shields.io/badge/AWS-IAM%20%7C%20CloudTrail-orange.svg)](https://aws.amazon.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**A comprehensive security assessment tool that analyzes AWS IAM access keys and generates actionable risk reports to strengthen your cloud security posture.**

[Features](#-features) • [Quick Start](#-quick-start) • [Risk Criteria](#-risk-criteria) • [Output](#-output-structure) • [Requirements](#-requirements)

---

</div>

## 🎯 Why Use This Tool?

In modern cloud environments, IAM access keys are one of the **most critical security risks**. Compromised or overprivileged keys can lead to:
- 💰 Unauthorized resource access and unexpected AWS bills
- 🚨 Data breaches and compliance violations
- 🔓 Lateral movement and privilege escalation attacks

**This tool helps you:**

| Goal | How We Help |
|------|-------------|
| 🛑 **Eliminate High-Risk Keys** | Identify and disable dangerous keys, migrate to temporary credentials (IAM roles, STS) |
| 🔒 **Apply Least Privilege** | Detect overprivileged keys and right-size permissions |
| 📊 **Prioritize Remediation** | Risk scoring (0-10) helps you focus on what matters most |
| ✅ **Maintain Compliance** | Regular auditing keeps your security posture strong |

### 🚀 What Makes This Different?

This isn't just another data collector—it's an **intelligent security analyst** that:
- ✨ Combines automated data gathering with deep risk analysis
- 🔍 Analyzes CloudTrail activity across **all AWS regions**
- 🏢 Supports **multi-account assessments** with consolidated reporting
- 📈 Uses **15+ security criteria** to calculate precise risk scores
- 📄 Generates reports in multiple formats (HTML, CSV, JSON) for different audiences

## ✨ Features

<table>
<tr>
<td width="50%">

### 🤖 Automated Intelligence
- 🔄 **One-Click Assessment** - Combines data gathering & analysis in single execution
- 🌐 **Multi-Region CloudTrail** - Queries all active AWS regions automatically
- 🏢 **Multi-Account Support** - Assess entire AWS organizations at once
- 📝 **Comprehensive Logging** - Detailed execution logs for troubleshooting

</td>
<td width="50%">

### 🔬 Deep Analysis
- 🎯 **15+ Risk Criteria** - Sophisticated scoring system (0-10 scale)
- 📋 **Policy Analysis** - Evaluates managed, customer, and inline policies
- 👤 **User Context** - Checks console access, MFA status, group memberships
- 🕵️ **CloudTrail Forensics** - Identifies read vs write operations

</td>
</tr>
<tr>
<td width="50%">

### 📊 Actionable Output
- 📄 **Multiple Formats** - Interactive HTML with charts, structured CSV, and JSON for automation
- 🗂️ **Organized Storage** - Timestamped folders for data versioning
- 🎨 **High-Risk Summary** - Focus on keys requiring immediate attention
- 📈 **Trend Analysis** - Compare assessments over time

</td>
<td width="50%">

### 🛡️ Security First
- 🔐 **Read-Only Operations** - No modifications to your AWS environment
- ✅ **Least Privilege** - Minimal IAM permissions required
- 🏆 **Best Practices** - Aligned with AWS Security Best Practices
- 📚 **Audit Trail** - Complete activity logging

</td>
</tr>
</table>

## 🎯 Risk Criteria

The tool uses a **15-point intelligent risk scoring system** to prioritize remediation efforts:

### 📊 Risk Score Scale

| Score Range | Severity | Action Required |
|-------------|----------|-----------------|
| 🔴 **8-10** | CRITICAL | Immediate attention - disable or rotate keys |
| 🟠 **5-7** | HIGH | Review within 48 hours - assess necessity |
| 🟡 **3-4** | MEDIUM | Schedule remediation - reduce permissions |
| 🟢 **1-2** | LOW | Monitor - document business justification |
| ⚪ **0** | NONE | Inactive keys - no immediate risk |

### 🔍 Evaluation Criteria

**Inactive Keys**: Automatically scored 0 (no further analysis)

**Active Keys** are evaluated against these criteria:

<details>
<summary><b>⏱️ Age & Usage Patterns (up to +3 points)</b></summary>

- ✅ Active key used in last 90 days **(+1)** - Recently active keys are attractive targets
- 📅 Active key created 90+ days ago **(+1)** - Older keys should be rotated
- ⏰ Active key created 360+ days ago **(+1)** - Year-old keys are high-risk

</details>

<details>
<summary><b>🔑 Permission & Privilege Analysis (up to +4.5 points)</b></summary>

- 👑 Associated with Admin/PowerUser AWS managed policies **(+1)** - Overprivileged keys
- ⚠️ Risky inline policies (wildcards, admin keywords) **(+1)** - Custom dangerous permissions
- 🎯 Admin access used in last 90 days **(+1)** - Active privileged usage
- 🔐 Can create/activate IAM keys **(+1)** - Self-replication capability
- 📝 Has custom inline policies **(+0.5)** - Non-standard configurations

</details>

<details>
<summary><b>👤 User Security Posture (up to +2 points)</b></summary>

- 🖥️ Associated user has console access **(+1)** - Dual access method
- 🚨 Console access without MFA **(+1)** - Vulnerable to credential theft

</details>

<details>
<summary><b>🕵️ CloudTrail Activity Analysis (up to +2 points)</b></summary>

- 📡 CloudTrail activity in last 90 days **(+1)** - Confirmed recent usage
- ✍️ Write operations detected **(+2)** - Modifying AWS resources

</details>

<details>
<summary><b>🏢 Environment Risk Factor (up to +2 points)</b></summary>

- 🏛️ Access key in management account **(+2)** - Highest security tier
- 🏭 Access key in production account **(+2)** - Business-critical environment
- 🧪 Access key in staging account **(+1)** - Pre-production environment

</details>

---

> **⚠️ Important Note on Pattern Matching**
>
> Some criteria use string pattern matching and may produce false positives/negatives:
> - **Admin/PowerUser detection**: Based on policy name patterns (customize for your org)
> - **Risky inline policies**: Keyword matching (`*`, `admin`, `full`, `iam:`, etc.)
> - **IAM key permissions**: Policy name and inline keyword detection
> - **Environment detection**: Account name matching (`production`, `prod`, `staging`)
>
> 💡 **Best Practice**: Always manually review flagged items to confirm actual risk levels based on your organization's naming conventions.

## 🚀 Quick Start

### 📋 Prerequisites

Before running the tool, ensure you have:

<table>
<tr>
<td width="50%">

**🐍 Python Environment**
```bash
# Python 3.6 or higher
python3 --version

# Install dependencies
pip3 install -r requirements.txt
```

</td>
<td width="50%">

**☁️ AWS Access**
- Valid AWS credentials configured
- IAM permissions (read-only, see below)
- AWS CLI v2 (recommended for multi-account)

</td>
</tr>
</table>

### 🔑 AWS Credentials Setup

Choose the method that works best for your environment:

| Method | Command | Best For |
|--------|---------|----------|
| 🏆 **AWS SSO** (Recommended) | `aws configure sso` | Multi-account organizations |
| 🔧 **AWS CLI** | `aws configure` | Single account access |
| 📝 **Named Profiles** | `aws configure --profile name` | Multiple independent accounts |
| 🌐 **Environment Variables** | Export `AWS_ACCESS_KEY_ID`, etc. | CI/CD pipelines |
| 🖥️ **IAM Roles** | Automatic on EC2 | Running on AWS infrastructure |

> 💡 **Multi-Account Tip**: Use AWS Identity Center (SSO) with CLI v2 for seamless access to multiple accounts without credential management overhead.

### 🔐 Required IAM Permissions

The tool requires **read-only** permissions. Create an IAM policy with these permissions:

<details>
<summary><b>📄 Click to view IAM policy JSON</b></summary>

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "account:GetAccountInformation",
        "organizations:DescribeOrganization",
        "cloudtrail:LookupEvents",
        "ec2:DescribeRegions",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:GetLoginProfile",
        "iam:ListMFADevices",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListGroupsForUser",
        "iam:ListGroups",
        "iam:ListAttachedGroupPolicies",
        "iam:ListGroupPolicies",
        "iam:GetGroupPolicy",
        "iam:ListAccountAliases",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

</details>

> 🔒 **Security Note**: These are all read-only permissions. The tool never modifies your AWS environment.

---

## 💻 Usage

### Basic Commands

```bash
# 🎯 Single account assessment (using default credentials)
python3 iam_risk_assessment.py

# 📋 Single account with specific profile
python3 iam_risk_assessment.py --profile my-aws-profile

# 🏢 Multi-account assessment (comma-separated profiles)
python3 iam_risk_assessment.py --profile prod,staging,dev

# 📂 Custom output directory
python3 iam_risk_assessment.py --profile my-profile --output-dir /path/to/reports

# ⚙️ Custom risk criteria config
python3 iam_risk_assessment.py --profile my-profile --config risk_config.yaml

# 🔄 Regenerate reports from previously gathered data
python3 iam_risk_assessment.py --report-only --data-dir gathered_data_20251010_143000
```

### 🔄 What Happens When You Run It?

```mermaid
graph LR
    A[🚀 Start] --> B[📊 Gather IAM Data]
    B --> C[🔍 Analyze Policies]
    C --> D[🕵️ Query CloudTrail]
    D --> E[📈 Calculate Risk Scores]
    E --> F[📄 Generate Reports]
    F --> G[✅ Complete]
```

1. **📊 Data Collection** - Gathers IAM users, access keys, policies, MFA status
2. **🔍 Deep Analysis** - Evaluates permissions, group memberships, inline policies
3. **🕵️ CloudTrail Forensics** - Queries all regions for recent key activity
4. **📈 Risk Scoring** - Applies 15+ criteria to calculate risk scores
5. **📄 Report Generation** - Creates HTML, CSV, and JSON reports in organized folders

### 🏢 Multi-Account Assessment

When assessing multiple accounts simultaneously, you get:

| Benefit | Description |
|---------|-------------|
| 📦 **Consolidated Data** | Single CSV files merging data from all accounts |
| 🔄 **Cross-Account Analysis** | Unified risk assessment across your AWS organization |
| 📊 **Centralized Reporting** | One comprehensive report covering all accounts |
| ⚡ **Efficiency** | Leverage AWS SSO for seamless multi-account access |
| 🎯 **Organization View** | Identify patterns and risks across account boundaries |

### ⚙️ Custom Risk Criteria

Customize the risk scoring criteria for your organization using a YAML or JSON config file:

```yaml
# risk_config.yaml
admin_policies:
  - AdministratorAccess
  - PowerUserAccess
  - MyOrgAdminPolicy

iam_key_policies:
  - IAMFullAccess
  - MyOrgIAMPolicy

risky_patterns:
  - "*"
  - "admin"
  - "iam:"
  - "my-org-sensitive-action"
```

```bash
python3 iam_risk_assessment.py --profile my-profile --config risk_config.yaml
```

Any keys omitted from the config file will use the built-in defaults.

### 🔄 Report-Only Mode

Regenerate reports from previously gathered data without making any AWS API calls:

```bash
# Regenerate reports with new output formats
python3 iam_risk_assessment.py --report-only --data-dir gathered_data_20251010_143000

# Regenerate with custom config and output location
python3 iam_risk_assessment.py --report-only --data-dir gathered_data_20251010_143000 \
  --config risk_config.yaml --output-dir /path/to/reports
```

### 📋 CLI Reference

| Flag | Description |
|------|-------------|
| `--profile` | AWS profile name(s), comma-separated for multi-account |
| `--output-dir` | Base path for output directories (default: current directory) |
| `--config` | Path to YAML/JSON risk criteria config file |
| `--report-only` | Generate reports from existing data (requires `--data-dir`) |
| `--data-dir` | Path to previously gathered data directory |

## 📁 Output Structure

The tool generates organized, timestamped directories for easy tracking and comparison:

```
📦 Your Working Directory
├── 📂 gathered_data_20251010_143000/          # 🗄️ Raw IAM data
│   ├── AWS-Accounts_*.csv
│   ├── IAMUser-AccessKey_*.csv
│   ├── IAMUser-ConsoleLogin_*.csv
│   ├── IAMUser-MFA_*.csv
│   ├── IAMUser-PoliciesSummary_*.csv
│   ├── IAMUser-InlinePoliciesChecks_*.csv
│   ├── IAMGroup-PoliciesSummary_*.csv
│   ├── IAMGroup-InlinePoliciesChecks_*.csv
│   └── CloudTrail-Events_*.csv                # 🕵️ Usage forensics
│
├── 📂 assessment_output_20251010_143000/      # 📊 Risk analysis reports
│   ├── iam_risk_report_*.html                 # 🌐 Interactive HTML with charts
│   ├── iam_risk_assessment_*.json             # 📋 Machine-readable JSON
│   ├── iam_risk_assessment_detailed_*.csv     # 📈 Complete dataset
│   └── iam_risk_assessment_summary_*.csv      # 🎯 High-risk keys only
│
└── 📄 iam_risk_assessment.log                 # 🔍 Execution logs
```

### 📊 Output Files Explained

<table>
<tr>
<th width="40%">File Type</th>
<th width="60%">Contents</th>
</tr>
<tr>
<td>

**🗄️ Gathered Data Directory**

`gathered_data_YYYYMMDD_HHMMSS/`

</td>
<td>

**Single Account:**
- Individual CSVs with account ID in filename
- Account-specific CloudTrail events

**Multi-Account (Consolidated):**
- Unified CSVs combining all accounts
- Cross-account CloudTrail analysis
- Complete IAM inventory across organization

</td>
</tr>
<tr>
<td>

**📊 Assessment Output Directory**

`assessment_output_YYYYMMDD_HHMMSS/`

</td>
<td>

1. **🌐 HTML Report** - Interactive dashboard with:
   - Chart.js visualizations (risk distribution, per-user scores, MFA status)
   - Color-coded risk score table
   - Overall statistics and summary cards

2. **📋 JSON Report** - Machine-readable output with:
   - Metadata (timestamp, account IDs)
   - Summary statistics
   - Detailed access key assessments

3. **📈 Detailed CSV** - Complete data for analysis tools

4. **🎯 Summary CSV** - High-risk keys only (score ≥ 5)

</td>
</tr>
<tr>
<td>

**🔍 Log File**

`iam_risk_assessment.log`

</td>
<td>

- Execution timeline and progress
- API calls and data collection stats
- Warnings and error messages
- CloudTrail query results

</td>
</tr>
</table>

### 📄 What's in the Reports?

The HTML report includes interactive Chart.js visualizations:

- 📊 **Risk Distribution** - Donut chart showing critical/high/medium/low breakdown
- 👤 **Per-User Risk Scores** - Horizontal bar chart of max risk score per user
- 🔐 **MFA Status** - Donut chart of MFA-enabled vs disabled active keys
- 📋 **Detailed Table** - All access keys sorted by risk score with:
  - Risk score bar with severity label
  - Key metadata (status, creation, last used)
  - Attached policies (managed and inline)
  - Console access and MFA badges
  - Risk factors list

The JSON report provides structured data for automation:

```json
{
  "metadata": { "generated_at": "...", "account_ids": ["..."] },
  "summary": { "total_keys": 5, "active_keys": 4, "inactive_keys": 1, "high_risk_keys": 3 },
  "access_keys": [{ "username": "...", "risk_score": 9, "risk_factors": ["..."], ... }]
}
```

## 📸 Example Output

Here's what the HTML report dashboard looks like:

![Sample Report](sample_report_screenshot.png)

Sample output files are available in the `sample_assessment_output/` directory, including HTML, CSV, and JSON reports generated from sanitized sample data.

---

## 🔧 Requirements

| Requirement | Version | Purpose |
|-------------|---------|---------|
| 🐍 **Python** | 3.6+ | Runtime environment |
| 📦 **boto3** | Latest | AWS SDK for Python |
| 📦 **pyyaml** | 6.0+ | YAML config file support |
| ☁️ **AWS Credentials** | - | Account access with read-only IAM permissions |
| 🔐 **IAM Permissions** | See above | Read access to IAM, CloudTrail, Organizations |

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd aws-iam-access-keys-risk-assessment

# Install dependencies
pip3 install -r requirements.txt

# Verify installation
python3 iam_risk_assessment.py --help
```

---

## 🛡️ Error Handling & Reliability

The tool includes **enterprise-grade error handling** for production environments:

| Error Type | Handling Strategy |
|------------|-------------------|
| 🔑 **AWS Credentials** | Clear error messages, credential setup guidance |
| 🚫 **Permission Denied** | Identifies missing IAM permissions |
| 🌐 **Network Issues** | Automatic retries with exponential backoff |
| 📡 **API Rate Limits** | Respectful throttling and pagination |
| 💾 **File I/O Errors** | Validates disk space, handles write failures |
| 🔍 **Data Parsing** | Graceful handling of unexpected API responses |
| 🏢 **Multi-Account Failures** | Continues assessment if one account fails |

All errors are logged to `iam_risk_assessment.log` with timestamps and context for troubleshooting.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided as-is for security assessment purposes. Always review and validate findings before taking action on production systems.

---

## 💡 Tips & Best Practices

- 🔄 **Run regularly** - Schedule weekly assessments to track security posture over time
- 📊 **Trend analysis** - Compare timestamped reports to identify new risks
- 👥 **Share reports** - Distribute summary CSV to stakeholders for review
- 🎯 **Prioritize** - Focus on high-risk keys (score ≥ 5) first
- 📝 **Document** - Record business justifications for necessary long-lived keys
- 🔒 **Remediate** - Migrate to IAM roles and temporary credentials where possible
- ✅ **Verify** - Re-run after remediation to confirm risk reduction

---
