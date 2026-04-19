"""Unit tests for CLI error conditions (Task 7.5),
run_complete_assessment HTML/JSON output (Task 8.1),
and --report-only mode (Task 8.2).
"""
import sys
import os
import copy
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from iam_risk_assessment import IAMCompleteAssessment, AccessKeyInfo, main


# ============================================================
# Task 7.5: CLI error conditions
# ============================================================

class TestCLIErrorConditions:
    """Tests for CLI argument validation errors."""

    def test_report_only_without_data_dir(self):
        """--report-only without --data-dir should sys.exit(1)."""
        test_args = ['prog', '--report-only']
        with patch('sys.argv', test_args):
            try:
                result = main()
                # main() calls sys.exit(1) which raises SystemExit
                assert False, "Expected SystemExit"
            except SystemExit as e:
                assert e.code == 1

    def test_config_nonexistent_file(self, tmp_path):
        """--config with nonexistent file should sys.exit(1)."""
        fake_config = str(tmp_path / "nonexistent.yaml")
        test_args = ['prog', '--config', fake_config]
        with patch('sys.argv', test_args):
            try:
                main()
                assert False, "Expected SystemExit"
            except SystemExit as e:
                assert e.code == 1

    def test_config_invalid_yaml(self, tmp_path):
        """--config with invalid YAML should sys.exit(1)."""
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("{{{{invalid: yaml: [[[")
        test_args = ['prog', '--config', str(bad_yaml)]
        with patch('sys.argv', test_args):
            try:
                main()
                assert False, "Expected SystemExit"
            except SystemExit as e:
                assert e.code == 1

    def test_data_dir_nonexistent_path(self, tmp_path):
        """--data-dir with nonexistent path should sys.exit(1)."""
        fake_dir = str(tmp_path / "nonexistent_dir")
        test_args = ['prog', '--report-only', '--data-dir', fake_dir]
        with patch('sys.argv', test_args):
            try:
                main()
                assert False, "Expected SystemExit"
            except SystemExit as e:
                assert e.code == 1


# ============================================================
# Task 8.1: run_complete_assessment produces HTML and JSON, no TXT
# ============================================================

class TestRunCompleteAssessment:
    """Verify run_complete_assessment() produces HTML and JSON but no TXT."""

    def test_produces_html_and_json_no_txt(self, tmp_path):
        """run_complete_assessment pipeline produces HTML/JSON, not TXT."""
        assessment = IAMCompleteAssessment(
            report_only=True,
            output_base_dir=str(tmp_path / "assessment"),
        )

        # Set up minimal data to run the analysis pipeline
        assessment.access_keys = [
            AccessKeyInfo(
                account_id="111111111111",
                username="testuser",
                user_id="AIDA111",
                arn="arn:aws:iam::111111111111:user/testuser",
                key_id="AKIA111",
                status="Active",
                last_used="2025-01-10 12:00:00",
                created="2024-01-01 00:00:00",
                has_console_access=False,
                has_mfa=False,
                managed_policies=[],
                inline_policies=[],
            )
        ]
        assessment.accounts = {"111111111111": "test-account"}
        assessment.gathered_data = {
            'accounts': [], 'access_keys': [], 'console_login': [],
            'mfa': [], 'user_policies': [], 'user_inline': [],
            'group_policies': [], 'group_inline': []
        }

        # Run the analysis + report generation pipeline
        # (skip gather_all_data since we're in report_only mode)
        assessment.load_accounts_from_data()
        assessment.calculate_risk_scores()
        detailed_csv, summary_csv = assessment.generate_csv_reports()
        json_file = assessment.generate_json_report()
        html_file = assessment.generate_html_report()

        # Assert HTML and JSON files exist
        assert html_file.exists(), "HTML file should exist"
        assert json_file.exists(), "JSON file should exist"
        assert str(html_file).endswith('.html')
        assert str(json_file).endswith('.json')

        # Assert no TXT files exist in assessment_dir
        txt_files = list(assessment.assessment_dir.glob("*.txt"))
        assert len(txt_files) == 0, f"No .txt files should exist, found: {txt_files}"


# ============================================================
# Task 8.2: --report-only mode generates HTML, CSV, JSON
# ============================================================

class TestReportOnlyMode:
    """Verify --report-only mode generates HTML, CSV, JSON from existing data."""

    def test_report_only_generates_all_formats(self, tmp_path):
        """--report-only with --data-dir generates HTML, CSV, JSON and no boto3 clients."""
        sample_dir = os.path.join(
            os.path.dirname(__file__), '..', 'sample_gathered_data'
        )
        sample_dir = os.path.abspath(sample_dir)

        # Ensure sample data exists
        assert os.path.isdir(sample_dir), f"sample_gathered_data not found at {sample_dir}"

        output_dir = str(tmp_path / "report_only_output")
        test_args = [
            'prog', '--report-only',
            '--data-dir', sample_dir,
            '--output-dir', output_dir,
        ]

        with patch('sys.argv', test_args):
            try:
                result = main()
            except SystemExit as e:
                result = e.code

        # main() should succeed (return 0)
        assert result == 0, f"main() should return 0, got {result}"

        # Find the assessment output directory
        output_path = Path(output_dir)
        assessment_dirs = list(output_path.glob("assessment_output_*"))
        assert len(assessment_dirs) == 1, f"Expected 1 assessment dir, found {assessment_dirs}"
        assessment_dir = assessment_dirs[0]

        # Verify HTML, CSV, and JSON files are generated
        html_files = list(assessment_dir.glob("*.html"))
        csv_files = list(assessment_dir.glob("*.csv"))
        json_files = list(assessment_dir.glob("*.json"))

        assert len(html_files) >= 1, f"Expected HTML files, found: {html_files}"
        assert len(csv_files) >= 1, f"Expected CSV files, found: {csv_files}"
        assert len(json_files) >= 1, f"Expected JSON files, found: {json_files}"

    def test_report_only_no_boto3_session(self, tmp_path):
        """In report-only mode, session should be None (no AWS API calls)."""
        assessment = IAMCompleteAssessment(
            report_only=True,
            output_base_dir=str(tmp_path / "no_boto"),
        )

        assert assessment.session is None, "session should be None in report_only mode"
        assert assessment.iam_client is None
        assert assessment.sts_client is None
        assert assessment.cloudtrail_client is None
