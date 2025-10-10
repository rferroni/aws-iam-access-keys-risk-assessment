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
- 📄 Generates reports in multiple formats (TXT, CSV) for different audiences

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
- 📄 **Multiple Formats** - Human-readable TXT + structured CSV reports
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
5. **📄 Report Generation** - Creates TXT and CSV reports in organized folders

### 🏢 Multi-Account Assessment

When assessing multiple accounts simultaneously, you get:

| Benefit | Description |
|---------|-------------|
| 📦 **Consolidated Data** | Single CSV files merging data from all accounts |
| 🔄 **Cross-Account Analysis** | Unified risk assessment across your AWS organization |
| 📊 **Centralized Reporting** | One comprehensive report covering all accounts |
| ⚡ **Efficiency** | Leverage AWS SSO for seamless multi-account access |
| 🎯 **Organization View** | Identify patterns and risks across account boundaries |

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
│   ├── iam_complete_assessment_report_*.txt   # 📄 Human-readable
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

1. **📄 Text Report** - Executive summary with:
   - Overall statistics and high-risk summary
   - Account-by-account breakdown
   - Detailed findings for each key

2. **📈 Detailed CSV** - Complete data for analysis tools

3. **🎯 Summary CSV** - High-risk keys only (score ≥ 5)

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

The comprehensive text report includes:

- ✅ **Overall Statistics** - Total keys, active/inactive counts, high-risk summary
- 🏢 **Account Breakdown** - Keys per account with proper account names
- 🚨 **High-Risk Summary** - Keys requiring immediate attention (score ≥ 5)
- 🔍 **Detailed Findings** - For each access key:
  - 📊 Risk score and contributing factors
  - 📅 Key metadata (status, creation, last used)
  - 🔑 Attached policies (managed, customer, inline)
  - 👥 Group memberships and inherited permissions
  - 🖥️ Console access and MFA status
  - 🕵️ CloudTrail activity (read vs write operations)

## 📸 Example Output

Here's what a typical assessment report looks like:

<details>
<summary><b>🔍 Click to view sample report output</b></summary>

```
================================================================================
IAM ACCESS KEY RISK ASSESSMENT REPORT
================================================================================
Generated: 2025-10-05 13:45:09

OVERALL STATISTICS
----------------------------------------
Total access keys found: 5
Active keys: 4
Inactive keys: 1
High-risk keys (score ≥ 5): 3

ACCESS KEYS BY ACCOUNT:
  111111111111 (Development Environment): 1 keys
  222222222222 (Production Account): 2 keys
  333333333333 (Staging Environment): 1 keys
  444444444444 (Management Account): 1 keys
  555555555555 (Security Account): 0 keys

HIGH-RISK ACCESS KEYS (Score ≥ 5)
----------------------------------------
• admin-user (AKIAEXAMPLE111111111) - Account: 444444444444 (Management Account) - Risk Score: 9
• prod-service (AKIAEXAMPLE222222222) - Account: 222222222222 (Production Account) - Risk Score: 7
• developer (AKIAEXAMPLE333333333) - Account: 111111111111 (Development Environment) - Risk Score: 5

DETAILED FINDINGS
----------------------------------------
1. User: admin-user
   Account: 444444444444 (Management Account)
   Key ID: AKIAEXAMPLE111111111
   Status: Active
   Created: 2023-06-15 10:30:00
   Last Used: 2025-10-03 14:22:00
   Risk Score: 9/10
   Risk Factors:
     - Active key used in last 90 days
     - Active key created 90+ days ago
     - Active key created 360+ days ago
     - Active key has admin/power user privileges
     - Active key with admin access used in last 90 days
     - Active key has write operations in CloudTrail (last 90 days)
     - Access key in management account
     - Associated user has console access
   Managed Policies: AdministratorAccess
   Console Access: Yes
   MFA Enabled: Yes

2. User: prod-service
   Account: 222222222222 (Production Account)
   Key ID: AKIAEXAMPLE222222222
   Status: Active
   Created: 2024-01-20 09:15:00
   Last Used: 2025-10-04 11:30:00
   Risk Score: 7/10
   Risk Factors:
     - Active key used in last 90 days
     - Active key created 90+ days ago
     - Active key created 360+ days ago
     - Active key has CloudTrail activity in last 90 days
     - Access key in production account
   Managed Policies: S3FullAccess, EC2ReadOnlyAccess
   Console Access: No
   MFA Enabled: Yes

3. User: developer
   Account: 111111111111 (Development Environment)
   Key ID: AKIAEXAMPLE333333333
   Status: Active
   Created: 2024-08-10 16:45:00
   Last Used: 2025-10-02 09:30:00
   Risk Score: 5/10
   Risk Factors:
     - Active key used in last 90 days
     - Active key created 90+ days ago
     - Active key has risky inline policies
     - Associated user has console access
     - Associated user doesn't have MFA enabled
   Inline Policies: CustomDevelopmentPolicy
   Console Access: Yes
   MFA Enabled: No

4. User: readonly-service
   Account: 333333333333 (Staging Environment)
   Key ID: AKIAEXAMPLE444444444
   Status: Active
   Created: 2025-09-01 12:00:00
   Last Used: 2025-10-01 08:15:00
   Risk Score: 3/10
   Risk Factors:
     - Active key used in last 90 days
     - Access key in staging account
   Managed Policies: ReadOnlyAccess
   Console Access: No
   MFA Enabled: Yes

5. User: legacy-user
   Account: 555555555555 (Security Account)
   Key ID: AKIAEXAMPLE555555555
   Status: Inactive
   Created: 2022-03-15 14:20:00
   Last Used: 2023-12-10 11:45:00
   Risk Score: 0/10
   Risk Factors: None (inactive key)
   Managed Policies: SecurityAuditAccess
   Console Access: Yes
   MFA Enabled: Yes
```

</details>

---

## 🔧 Requirements

| Requirement | Version | Purpose |
|-------------|---------|---------|
| 🐍 **Python** | 3.6+ | Runtime environment |
| 📦 **boto3** | Latest | AWS SDK for Python |
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
