"""Property tests for JSON round-trip (Property 1) and
JSON structure completeness (Property 2).

Validates: Requirements 2.2, 2.4, 2.5
"""
import sys
import os
import json
import copy

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from hypothesis import given, settings
from hypothesis import strategies as st

from iam_risk_assessment import AccessKeyInfo, IAMCompleteAssessment

# Strategy for generating AccessKeyInfo objects
safe_text = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789_-",
    min_size=1,
    max_size=15,
)

access_key_strategy = st.builds(
    AccessKeyInfo,
    account_id=st.text(alphabet="0123456789", min_size=12, max_size=12),
    username=safe_text,
    user_id=safe_text,
    arn=safe_text,
    key_id=safe_text,
    status=st.sampled_from(["Active", "Inactive"]),
    last_used=st.one_of(st.none(), safe_text),
    created=st.one_of(st.none(), safe_text),
    risk_score=st.integers(min_value=0, max_value=10),
    risk_factors=st.lists(safe_text, max_size=5),
    has_console_access=st.booleans(),
    has_mfa=st.booleans(),
    managed_policies=st.lists(safe_text, max_size=5),
    inline_policies=st.lists(safe_text, max_size=5),
)


def _make_unique_keys(keys):
    """Assign unique key_ids to avoid collisions in round-trip lookup."""
    for i, k in enumerate(keys):
        k.key_id = f"AKIA{i:08d}"
    return keys


@settings(max_examples=50)
@given(keys=st.lists(access_key_strategy, min_size=1, max_size=10))
def test_json_round_trip(keys, tmp_path_factory):
    """**Validates: Requirements 2.4, 2.5**

    For any list of AccessKeyInfo objects, serializing them to a JSON
    report and deserializing the file should produce matching fields.
    """
    tmp_path = tmp_path_factory.mktemp("json_rt")
    keys = _make_unique_keys(copy.deepcopy(keys))

    assessment = IAMCompleteAssessment(
        report_only=True,
        output_base_dir=str(tmp_path),
    )
    assessment.access_keys = copy.deepcopy(keys)
    assessment.accounts = {k.account_id: "test-account" for k in keys}
    assessment.gathered_data = {'user_inline': []}

    json_path = assessment.generate_json_report()

    with open(json_path, 'r', encoding='utf-8') as f:
        report = json.load(f)

    # Build lookup by unique key_id
    original_by_key = {k.key_id: k for k in keys}

    assert len(report["access_keys"]) == len(keys)

    for entry in report["access_keys"]:
        key_id = entry["key_id"]
        assert key_id in original_by_key, f"Unexpected key_id in JSON: {key_id}"
        orig = original_by_key[key_id]

        assert entry["username"] == orig.username
        assert entry["status"] == orig.status
        assert entry["risk_score"] == orig.risk_score
        assert entry["risk_factors"] == orig.risk_factors
        assert entry["managed_policies"] == orig.managed_policies
        assert entry["inline_policies"] == orig.inline_policies
        assert entry["console_access"] == orig.has_console_access
        assert entry["mfa_enabled"] == orig.has_mfa


@settings(max_examples=50)
@given(keys=st.lists(access_key_strategy, min_size=0, max_size=10))
def test_json_structure_completeness(keys, tmp_path_factory):
    """**Validates: Requirements 2.2**

    The JSON report should contain exactly three top-level keys:
    metadata, summary, and access_keys with correct sub-keys.
    """
    tmp_path = tmp_path_factory.mktemp("json_struct")

    assessment = IAMCompleteAssessment(
        report_only=True,
        output_base_dir=str(tmp_path),
    )
    assessment.access_keys = copy.deepcopy(keys)
    assessment.accounts = {k.account_id: "test-account" for k in keys}
    assessment.gathered_data = {'user_inline': []}

    json_path = assessment.generate_json_report()

    with open(json_path, 'r', encoding='utf-8') as f:
        report = json.load(f)

    # Top-level keys
    assert set(report.keys()) == {"metadata", "summary", "access_keys"}

    # metadata sub-keys
    assert "generated_at" in report["metadata"]
    assert "account_ids" in report["metadata"]

    # summary sub-keys
    assert set(report["summary"].keys()) == {
        "total_keys", "active_keys", "inactive_keys", "high_risk_keys"
    }

    # access_keys length matches input
    assert len(report["access_keys"]) == len(keys)
