"""Tests for api.translate."""
import pytest

from api.models import AuthMethod, Severity
from api.translate import severity_for


class TestSeverityFor:
    @pytest.mark.parametrize("method", [AuthMethod.ntlm, AuthMethod.basic])
    def test_blockers(self, method):
        assert severity_for(method) == Severity.blocker

    @pytest.mark.parametrize("method", [AuthMethod.negotiate, AuthMethod.unknown])
    def test_review(self, method):
        assert severity_for(method) == Severity.review

    @pytest.mark.parametrize(
        "method",
        [
            AuthMethod.kerberos,
            AuthMethod.oauth,
            AuthMethod.bearer,
            AuthMethod.mtls,
            AuthMethod.unauthenticated,
        ],
    )
    def test_cleared(self, method):
        assert severity_for(method) == Severity.cleared

    def test_every_auth_method_is_mapped(self):
        # Guards against a new AuthMethod slipping through without a severity.
        for method in AuthMethod:
            assert isinstance(severity_for(method), Severity)
