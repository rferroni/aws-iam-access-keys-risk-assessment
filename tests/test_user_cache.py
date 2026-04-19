"""Property test for user cache equivalence (Property 3).

Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7

For any set of IAM user data, calling gather_iam_users() multiple times
on the same IAMCompleteAssessment instance should return the same list
and should invoke the IAM list_users paginator exactly once.
"""
import sys
import os
import tempfile
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from iam_risk_assessment import IAMCompleteAssessment


def test_gather_iam_users_cache_equivalence(tmp_path):
    """**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7**

    Calling gather_iam_users() twice returns the same list and
    the paginator's paginate() is called exactly once.
    """
    assessment = IAMCompleteAssessment(
        report_only=True,
        output_base_dir=str(tmp_path / "cache_test"),
    )

    # Ensure cache is empty
    assessment._users_cache = None

    # Set up mock IAM client with paginator
    fake_users = [
        {"UserName": "alice", "UserId": "AIDA1", "Arn": "arn:aws:iam::111:user/alice"},
        {"UserName": "bob", "UserId": "AIDA2", "Arn": "arn:aws:iam::111:user/bob"},
        {"UserName": "charlie", "UserId": "AIDA3", "Arn": "arn:aws:iam::111:user/charlie"},
    ]

    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"Users": fake_users}]

    mock_iam_client = MagicMock()
    mock_iam_client.get_paginator.return_value = mock_paginator

    assessment.iam_client = mock_iam_client

    # First call - should fetch from paginator
    result1 = assessment.gather_iam_users()
    # Second call - should return cached result
    result2 = assessment.gather_iam_users()

    # Both calls return the same list
    assert result1 == result2
    assert result1 is result2  # Same object reference (cached)
    assert result1 == fake_users

    # Paginator's paginate() was called exactly once
    mock_paginator.paginate.assert_called_once()
