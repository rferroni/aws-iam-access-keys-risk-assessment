"""Property test for output directory creation (Property 4).

Validates: Requirements 4.2, 4.4

For any valid filesystem path string provided as output_base_dir,
the IAMCompleteAssessment constructor should create both
gathered_data_{timestamp} and assessment_output_{timestamp} as
subdirectories under that base path.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pathlib import Path
from hypothesis import given, settings
from hypothesis import strategies as st

from iam_risk_assessment import IAMCompleteAssessment


@settings(max_examples=50)
@given(
    dir_name=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz",
        min_size=1,
        max_size=20,
    )
)
def test_output_directory_creation(dir_name, tmp_path_factory):
    """**Validates: Requirements 4.2, 4.4**

    Verify both gathered_data_{timestamp} and assessment_output_{timestamp}
    dirs exist under the base path, including parent directory creation.
    """
    tmp_path = tmp_path_factory.mktemp("outdir")
    base_path = tmp_path / dir_name

    assessment = IAMCompleteAssessment(
        report_only=True,
        output_base_dir=str(base_path),
    )

    # The base path should have been created
    assert base_path.exists(), f"Base path {base_path} was not created"

    # Both timestamped directories should exist under the base path
    ts = assessment.timestamp
    gathered_dir = base_path / f"gathered_data_{ts}"
    assessment_dir = base_path / f"assessment_output_{ts}"

    assert gathered_dir.exists(), f"gathered_data dir not found: {gathered_dir}"
    assert assessment_dir.exists(), f"assessment_output dir not found: {assessment_dir}"
    assert gathered_dir.is_dir()
    assert assessment_dir.is_dir()
