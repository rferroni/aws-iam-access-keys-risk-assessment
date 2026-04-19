"""Property tests for config loading with default merge (Property 5)
and default config scoring equivalence (Property 6).

Validates: Requirements 5.2, 5.6, 5.7
"""
import sys
import os
import copy
import tempfile
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from iam_risk_assessment import AccessKeyInfo, IAMCompleteAssessment, load_risk_config

# Hardcoded defaults from the source
DEFAULT_ADMIN_POLICIES = {
    'AdministratorAccess', 'PowerUserAccess', 'IAMFullAccess',
    'AWSCloudTrailFullAccess', 'AmazonEC2FullAccess'
}
DEFAULT_IAM_KEY_POLICIES = {
    'IAMFullAccess', 'IAMUserChangePassword', 'IAMReadOnlyAccess'
}
DEFAULT_RISKY_PATTERNS = [
    '*', 'admin', 'full', 'all', 'root', 'super',
    'iam:', 'sts:', 'organizations:', 'account:',
    'createaccesskey', 'deleteaccesskey', 'updateaccesskey',
    'createrole', 'deleterole', 'attachrolepolicy',
    'createuser', 'deleteuser', 'attachuserpolicy'
]

ALL_CONFIG_KEYS = ['admin_policies', 'iam_key_policies', 'risky_patterns']

config_values = {
    'admin_policies': ['CustomAdmin', 'SuperAccess'],
    'iam_key_policies': ['CustomIAM'],
    'risky_patterns': ['custom_pattern', 'dangerous'],
}


@settings(max_examples=50)
@given(subset=st.sets(st.sampled_from(ALL_CONFIG_KEYS)))
def test_config_loading_default_merge(subset, tmp_path_factory):
    """**Validates: Requirements 5.2, 5.6**

    For any subset of config keys, loading the config and merging with
    defaults should produce criteria where present keys match the file
    values and absent keys match the hardcoded defaults.
    """
    tmp_path = tmp_path_factory.mktemp("config")

    # Build a config dict with only the selected subset of keys
    config_data = {}
    for key in subset:
        config_data[key] = config_values[key]

    # Write to a temp YAML file
    config_file = tmp_path / "test_config.yaml"
    with open(config_file, 'w') as f:
        yaml.dump(config_data, f)

    # Load the config
    loaded = load_risk_config(str(config_file))

    # Create assessment with the loaded config
    assessment = IAMCompleteAssessment(
        report_only=True,
        output_base_dir=str(tmp_path / "output"),
        risk_config=loaded,
    )

    # Verify: present keys match file values
    if 'admin_policies' in subset:
        assert assessment.admin_policies == set(config_values['admin_policies'])
    else:
        assert assessment.admin_policies == DEFAULT_ADMIN_POLICIES

    if 'iam_key_policies' in subset:
        assert assessment.iam_key_policies == set(config_values['iam_key_policies'])
    else:
        assert assessment.iam_key_policies == DEFAULT_IAM_KEY_POLICIES

    if 'risky_patterns' in subset:
        assert assessment.risky_patterns == config_values['risky_patterns']
    else:
        assert assessment.risky_patterns == DEFAULT_RISKY_PATTERNS


# Strategy for generating AccessKeyInfo objects
access_key_strategy = st.builds(
    AccessKeyInfo,
    account_id=st.just("111111111111"),
    username=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=10),
    user_id=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", min_size=5, max_size=10),
    arn=st.just("arn:aws:iam::111111111111:user/testuser"),
    key_id=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", min_size=5, max_size=10),
    status=st.sampled_from(["Active", "Inactive"]),
    last_used=st.just("2025-01-10 12:00:00"),
    created=st.just("2024-01-01 00:00:00"),
    risk_score=st.just(0),
    risk_factors=st.just([]),
    has_console_access=st.booleans(),
    has_mfa=st.booleans(),
    managed_policies=st.lists(st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=10), max_size=3),
    inline_policies=st.lists(st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=10), max_size=3),
)


@settings(max_examples=50)
@given(keys=st.lists(access_key_strategy, min_size=0, max_size=5))
def test_default_config_scoring_equivalence(keys, tmp_path_factory):
    """**Validates: Requirements 5.7**

    Calculating risk scores with a config file that contains the same
    values as the hardcoded defaults should produce identical risk scores
    and risk factors as calculating with no config file.
    """
    tmp_path = tmp_path_factory.mktemp("scoring")

    # Deep copy keys for both assessments
    keys_no_config = copy.deepcopy(keys)
    keys_with_config = copy.deepcopy(keys)

    # Assessment 1: no risk_config (defaults)
    a1 = IAMCompleteAssessment(
        report_only=True,
        output_base_dir=str(tmp_path / "a1"),
    )
    a1.session = None
    a1.access_keys = keys_no_config
    a1.accounts = {"111111111111": "test-account"}
    a1.gathered_data = {'user_inline': []}
    a1.calculate_risk_scores()

    # Assessment 2: risk_config matching hardcoded defaults exactly
    explicit_config = {
        'admin_policies': list(DEFAULT_ADMIN_POLICIES),
        'iam_key_policies': list(DEFAULT_IAM_KEY_POLICIES),
        'risky_patterns': DEFAULT_RISKY_PATTERNS,
    }
    a2 = IAMCompleteAssessment(
        report_only=True,
        output_base_dir=str(tmp_path / "a2"),
        risk_config=explicit_config,
    )
    a2.session = None
    a2.access_keys = keys_with_config
    a2.accounts = {"111111111111": "test-account"}
    a2.gathered_data = {'user_inline': []}
    a2.calculate_risk_scores()

    # Verify risk_scores and risk_factors are identical
    assert len(a1.access_keys) == len(a2.access_keys)
    for k1, k2 in zip(a1.access_keys, a2.access_keys):
        assert k1.risk_score == k2.risk_score, (
            f"Risk scores differ for {k1.username}: {k1.risk_score} vs {k2.risk_score}"
        )
        assert k1.risk_factors == k2.risk_factors, (
            f"Risk factors differ for {k1.username}: {k1.risk_factors} vs {k2.risk_factors}"
        )
