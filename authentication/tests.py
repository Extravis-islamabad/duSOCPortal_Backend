"""
Tests for the SAML portal boundary.

These cover authentication.saml helpers that are pure functions over a user's
role flags and an untrusted portal hint. They need no database and no SAML
library, so they run without python3-saml or xmlsec1 installed.

The boundary matters because password login enforces it implicitly - which AD
tree you bind against decides which portal you reach - while SAML has a single
IdP and a single ACS, so it has to be enforced explicitly here.
"""

from django.test import SimpleTestCase

from authentication.saml import (
    PORTAL_ADMIN,
    PORTAL_CLIENT,
    resolve_portal,
    user_allowed_in_portal,
)


class FakeUser:
    """A user with only the flags user_allowed_in_portal reads."""

    def __init__(self, **flags):
        self.is_admin = False
        self.is_super_admin = False
        self.is_read_only = False
        self.is_tenant = False
        for name, value in flags.items():
            setattr(self, name, value)


class UserAllowedInPortalTests(SimpleTestCase):
    def test_admin_flags_allow_admin_portal_only(self):
        for flag in ("is_admin", "is_super_admin", "is_read_only"):
            with self.subTest(flag=flag):
                user = FakeUser(**{flag: True})
                self.assertTrue(user_allowed_in_portal(user, PORTAL_ADMIN))
                self.assertFalse(user_allowed_in_portal(user, PORTAL_CLIENT))

    def test_tenant_allows_client_portal_only(self):
        user = FakeUser(is_tenant=True)
        self.assertTrue(user_allowed_in_portal(user, PORTAL_CLIENT))
        self.assertFalse(user_allowed_in_portal(user, PORTAL_ADMIN))

    def test_no_flags_allows_neither_portal(self):
        user = FakeUser()
        self.assertFalse(user_allowed_in_portal(user, PORTAL_ADMIN))
        self.assertFalse(user_allowed_in_portal(user, PORTAL_CLIENT))

    def test_admin_flags_win_over_is_tenant(self):
        """
        A user carrying both an admin flag and is_tenant belongs to the admin
        portal, because UserDetailSerializer resolves them to role "admin" and
        the frontend refuses them on the client portal. Allowing the client
        portal here would mint a token pair the frontend then rejects.
        """
        for flag in ("is_admin", "is_super_admin", "is_read_only"):
            with self.subTest(flag=flag):
                user = FakeUser(is_tenant=True, **{flag: True})
                self.assertTrue(user_allowed_in_portal(user, PORTAL_ADMIN))
                self.assertFalse(user_allowed_in_portal(user, PORTAL_CLIENT))


class ResolvePortalTests(SimpleTestCase):
    """
    The portal hint reaches us twice through the browser - as a query parameter
    and then as RelayState - so it is entirely attacker-controlled and must
    never escape the allow-list.
    """

    def test_valid_values_are_accepted(self):
        self.assertEqual(resolve_portal("admin"), PORTAL_ADMIN)
        self.assertEqual(resolve_portal("client"), PORTAL_CLIENT)

    def test_case_and_whitespace_are_normalised(self):
        self.assertEqual(resolve_portal("ADMIN"), PORTAL_ADMIN)
        self.assertEqual(resolve_portal("  Client  "), PORTAL_CLIENT)

    def test_crafted_values_never_escape_the_allow_list(self):
        crafted = [
            "https://evil.com",
            "//evil.com",
            "javascript:alert(1)",
            "../../etc/passwd",
            "admin\x00",
            "admin ",
            "",
            None,
            [],
        ]
        for value in crafted:
            with self.subTest(value=repr(value)):
                self.assertIn(resolve_portal(value), (PORTAL_ADMIN, PORTAL_CLIENT))

    def test_crafted_values_do_not_reach_the_admin_portal(self):
        for value in ("https://evil.com", "//evil.com", "ADMIN\x00", None, ""):
            with self.subTest(value=repr(value)):
                self.assertEqual(resolve_portal(value), PORTAL_CLIENT)
