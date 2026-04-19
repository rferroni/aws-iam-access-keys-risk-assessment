# Sample Data

This directory contains sanitized sample output files to demonstrate the tool's capabilities without exposing real AWS data.

## Sample Directories

- `sample_gathered_data/` - Example of raw data collected from AWS APIs
- `sample_assessment_output/` - Example of risk assessment reports and analysis

## Data Obfuscation

All sample data has been sanitized:
- **AWS Account IDs**: Replaced with fake IDs (111111111111, 222222222222, etc.)
- **Access Key IDs**: Replaced with AKIAEXAMPLE* format
- **User IDs**: Replaced with AIDAEXAMPLE* format
- **Usernames**: Generic names (admin-user, prod-service, developer, etc.)
- **Account Names**: Generic environment names
- **IP Addresses**: RFC 5737 test addresses (203.0.113.x, 192.0.2.x, 198.51.100.x)
- **ARNs**: Consistent with fake account IDs

## Real Data Protection

The `.gitignore` file prevents real assessment data from being committed:
- `gathered_data_*/` - Real gathered data folders
- `assessment_output_*/` - Real assessment output folders
- `*.log` - Log files containing real data

## Usage

These sample files demonstrate:
1. The structure and format of gathered AWS data
2. Risk assessment scoring and analysis
3. Report generation capabilities (HTML, CSV, JSON)
4. CloudTrail integration features

You can regenerate sample reports from the sample data using:
```bash
python3 iam_risk_assessment.py --report-only --data-dir sample_gathered_data --output-dir sample_output
```

When you run the actual tool, it will create timestamped directories with real data that will be automatically ignored by git.
