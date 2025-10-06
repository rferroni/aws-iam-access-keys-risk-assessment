# IAM Risk Assessment Tool

## Introduction

This comprehensive AWS IAM access key risk assessment tool analyzes user access keys and generates detailed security risk reports. The tool evaluates access keys against multiple security criteria, calculates risk scores, and produces reports in various formats to help organizations identify and mitigate IAM security risks.

## Objective

The primary goal is to help security administrators identify access keys that require immediate attention. The tool enables organizations to:

- **Disable high-risk keys** and migrate to temporary credentials (IAM roles, STS tokens)
- **Apply principle of least privilege** by removing excessive permissions from necessary keys
- **Prioritize remediation efforts** based on calculated risk scores
- **Maintain security compliance** through regular access key auditing

This Python script combines automated IAM data gathering with comprehensive risk assessment analysis. It uses boto3 to collect IAM data directly from AWS accounts and immediately performs security risk analysis.

## Features

- **Automated Data Collection**: Uses boto3 to gather IAM data directly from AWS accounts
- **Complete Analysis**: Analyzes user and group policies (managed, customer managed, and inline)
- **Risk Scoring**: Calculates risk scores (0-10) based on 15 security criteria
- **Organized Output**: Creates timestamped folders for gathered data and assessment results
- **Multiple Formats**: Generates text reports and CSV files for analysis
- **Single Execution**: Combines data gathering and risk assessment in one command
- **Comprehensive Logging**: Tracks both data collection and analysis phases
- **CloudTrail Integration**: Analyzes access key usage patterns across all AWS regions
- **Multi-Region Support**: Queries CloudTrail events from all active AWS regions

## Risk Criteria

The script evaluates each access key with improved logic:

**Inactive Keys**: Risk score = 0 (no further evaluation)

**Active Keys** are evaluated against these criteria:
1. Active key used in last 90 days (+1)
2. Active key created 90+ days ago (+1)
3. Active key created 360+ days ago (+1)
4. Active key associated with Admin/PowerUser AWS managed policies (+1)
5. Active key with risky inline policies (containing admin-like permissions) (+1)
6. Active key with admin access used in last 90 days (+1)
7. Active key with permissions to create/activate IAM keys (+1)
8. Active key has custom inline policies (+0.5 if not risky)
9. Associated user has console access (+1)
10. Associated user doesn't have MFA enabled (only checked if user has console access) (+1)
11. Access key has CloudTrail activity in last 90 days (+1)
12. Access key has write operations in CloudTrail (last 90 days) (+2)
13. Access key in management account (+2)
14. Access key in production account (+2)
15. Access key in staging account (+1)

**Important Note:** Some risk criteria rely on string pattern matching and may produce false positives or negatives:
- **Criteria #4**: Admin/PowerUser policy detection uses predefined policy name patterns
- **Criteria #5**: Risky inline policies detected through keyword matching (*, admin, full, iam:, etc.)
- **Criteria #7**: IAM key permissions identified by policy name patterns and inline policy keywords
- **Criteria #14-15**: Production/staging account detection based on account name string matching ('production', 'prod', 'staging')

Review flagged items manually to confirm actual risk levels, as naming conventions may vary across organizations.

## Prerequisites

- **AWS Credentials**: Configure AWS credentials using one of these methods (recommended order):
  - **AWS Identity Center (SSO) with CLI v2** (Recommended): `aws configure sso` - allows multiple profiles in same session
  - AWS CLI: `aws configure` or individual profiles with `aws configure --profile profile-name`
  - Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
  - IAM roles (for EC2 instances)

- **Multi-Account Assessment**: For assessing multiple AWS accounts, use AWS Identity Center with CLI v2 to configure multiple profiles under the same SSO session. This provides seamless access to multiple accounts without credential management overhead.

- **Required Permissions**: The AWS credentials must have the following IAM permissions:
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

## Usage

```bash
# Run complete assessment with default AWS credentials
python3 iam_risk_assessment.py

# Use specific AWS profile
python3 iam_risk_assessment.py --profile your-profile-name

# Use multiple AWS profiles (comma-separated) - for multi-account assessment
python3 iam_risk_assessment.py --profile profile1,profile2,profile3

# The script will:
# 1. Gather all IAM data from your AWS account(s)
# 2. Perform comprehensive risk analysis
# 3. Generate consolidated data files and reports across all accounts
```

### Multi-Account Assessment Benefits

When using multiple profiles, the tool provides:
- **Consolidated Data Files**: Single CSV files containing data from all accounts
- **Cross-Account Risk Analysis**: Unified risk assessment across your AWS organization
- **Centralized Reporting**: One comprehensive report covering all assessed accounts
- **Efficient Credential Management**: Leverage AWS Identity Center for seamless multi-account access

## Output Structure

The script creates two timestamped directories:

### 1. Gathered Data Directory: `gathered_data_YYYYMMDD_HHMMSS/`

**Single Account Assessment:**
- `AWS-Accounts_ACCOUNTID_YYYYMMDD_HHMMSS.csv`: Account information
- `IAMUser-AccessKey_ACCOUNTID_YYYYMMDD_HHMMSS.csv`: Access key details
- `CloudTrail-Events_ACCOUNTID_YYYYMMDD_HHMMSS.csv`: CloudTrail activity
- (Additional files with account-specific naming)

**Multi-Account Assessment (Consolidated Files):**
- `AWS-Accounts_YYYYMMDD_HHMMSS.csv`: All account information
- `IAMUser-AccessKey_YYYYMMDD_HHMMSS.csv`: All access key details
- `IAMUser-ConsoleLogin_YYYYMMDD_HHMMSS.csv`: All console access data
- `IAMUser-MFA_YYYYMMDD_HHMMSS.csv`: All MFA device information
- `IAMUser-PoliciesSummary_YYYYMMDD_HHMMSS.csv`: All user policy attachments
- `IAMUser-InlinePoliciesChecks_YYYYMMDD_HHMMSS.csv`: All user inline policies
- `IAMGroup-PoliciesSummary_YYYYMMDD_HHMMSS.csv`: All group policy attachments
- `IAMGroup-InlinePoliciesChecks_YYYYMMDD_HHMMSS.csv`: All group inline policies
- `CloudTrail-Events_YYYYMMDD_HHMMSS.csv`: CloudTrail activity for all access keys across all accounts

### 2. Assessment Output Directory: `assessment_output_YYYYMMDD_HHMMSS/`
- `iam_complete_assessment_report_YYYYMMDD_HHMMSS.txt`: Human-readable comprehensive report
- `iam_risk_assessment_detailed_YYYYMMDD_HHMMSS.csv`: Complete analysis data
- `iam_risk_assessment_summary_YYYYMMDD_HHMMSS.csv`: High-risk keys only (score ≥ 5)

### 3. Log File: `iam_risk_assessment.log`

**Report Contents:**
- Overall statistics (total keys, active/inactive counts, high-risk key count)
- Access keys breakdown by AWS account (with proper account names)
- High-risk keys summary (score ≥ 5)
- Detailed findings for each access key including:
  - Risk score and contributing factors
  - Key details (status, creation date, last used)
  - User and group policies (managed and inline)
  - Console access and MFA status
  - CloudTrail activity analysis (read-only vs write operations)

## Example Output

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

## Requirements

- Python 3.6+
- boto3 (AWS SDK for Python)
- Valid AWS credentials with required IAM permissions

## Error Handling

The script includes comprehensive error handling for:
- AWS credential and permission issues
- Network connectivity problems
- Invalid AWS API responses
- File I/O errors
- Data parsing issues

All errors are logged to `iam_risk_assessment.log` for troubleshooting.