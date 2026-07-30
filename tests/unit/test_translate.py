"""Tests for api.translate."""
import pytest

from api.models import AuthMethod, Severity
from api.translate import severity_for, tag_to_auth_method


class TestSeverityFor:
    @pytest.mark.parametrize("auth_method", [AuthMethod.ntlm, AuthMethod.basic])
    def test_blockers(self, auth_method):
        assert severity_for(auth_method) == Severity.blocker

    @pytest.mark.parametrize(
        "auth_method", [AuthMethod.negotiate, AuthMethod.unknown, AuthMethod.other]
    )
    def test_review(self, auth_method):
        assert severity_for(auth_method) == Severity.review

    @pytest.mark.parametrize(
        "auth_method",
        [
            AuthMethod.kerberos,
            AuthMethod.oauth,
            AuthMethod.bearer,
            AuthMethod.mtls,
            AuthMethod.unauthenticated,
        ],
    )
    def test_cleared(self, auth_method):
        assert severity_for(auth_method) == Severity.cleared

    def test_every_auth_method_is_mapped(self):
        # Guards against a new AuthMethod slipping through without a severity.
        for auth_method in AuthMethod:
            assert isinstance(severity_for(auth_method), Severity)


class TestTagToAuthMethod:
    def test_other_marker_maps_to_other(self):
        # The interceptor's else-branch 401 challenge -> AuthMethod.other.
        assert tag_to_auth_method("other") == AuthMethod.other

    def test_unclassified_stays_unknown(self):
        assert tag_to_auth_method("something weird") == AuthMethod.unknown
