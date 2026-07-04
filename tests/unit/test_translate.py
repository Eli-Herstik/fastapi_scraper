"""Tests for api.translate."""
import pytest

from api.models import AuthMethod, Severity
from api.translate import normalize_auth_method, severity_for


class TestSeverityFor:
    @pytest.mark.parametrize("method", [AuthMethod.ntlm, AuthMethod.basic])
    def test_blockers(self, method):
        assert severity_for(method) == Severity.blocker

    @pytest.mark.parametrize("method", [AuthMethod.negotiate, AuthMethod.unknown, AuthMethod.other])
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


class TestNormalizeAuthMethod:
    def test_other_marker_maps_to_other(self):
        # The interceptor's else-branch 401 challenge -> AuthMethod.other.
        assert (
            normalize_auth_method('Required: Other (Digest realm="t")')
            == AuthMethod.other
        )

    def test_other_marker_does_not_preempt_real_scheme(self):
        # A bare NTLM 401 also flows through the "Other" marker, but must still
        # resolve to ntlm (a blocker) -- the "other" check runs last.
        assert normalize_auth_method("Required: Other (NTLM)") == AuthMethod.ntlm

    def test_unclassified_stays_unknown(self):
        assert normalize_auth_method("something weird") == AuthMethod.unknown
