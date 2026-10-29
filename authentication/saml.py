"""
SAML 2.0 Service Provider helpers.

All python3-saml / OneLogin specifics live here so that the views stay thin,
mirroring how common/modules/* keeps vendor HTTP out of the Celery tasks.

The portal is the Service Provider; FortiAuthenticator is the Identity
Provider. SAML replaces only the credential check: once an assertion has been
validated the ACS view issues the same SimpleJWT pair as the password login,
so nothing downstream is aware that SSO exists.

Single Logout is deliberately out of scope for phase one - see
SAML_Integration_Meeting_QA.md. No SLS endpoint is published and no
SessionIndex is stored.
"""

from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from loguru import logger

from common.constants import SAMLConstants

XML_DECLARATION = '<?xml version="1.0" encoding="UTF-8"?>' + chr(10)

try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.settings import OneLogin_Saml2_Settings

    SAML_LIBRARY_AVAILABLE = True
except ImportError:  # pragma: no cover - python3-saml not installed
    OneLogin_Saml2_Auth = None
    OneLogin_Saml2_Settings = None
    SAML_LIBRARY_AVAILABLE = False
    logger.warning(
        "python3-saml is not installed; SAML endpoints will be unavailable. "
        "Install it and the xmlsec1 system libraries to enable SSO."
    )


#: The portal a login started from. Carried across the IdP round-trip in
#: RelayState and used as a key into the callback allow-list.
PORTAL_ADMIN = "admin"
PORTAL_CLIENT = "client"
VALID_PORTALS = (PORTAL_ADMIN, PORTAL_CLIENT)


def saml_available() -> bool:
    """True only when SSO is switched on and the library is importable."""
    return SAMLConstants.SAML_ENABLED and SAML_LIBRARY_AVAILABLE


def resolve_portal(value) -> str:
    """
    Reduce an untrusted portal hint to one of VALID_PORTALS.

    The hint reaches us twice through the browser: as a query parameter on
    /saml/login/, then back as RelayState on the ACS POST. Both are entirely
    attacker-controllable, so it is treated as an opaque key and anything
    unrecognised falls back to the configured default. It is never used to
    build a URL.
    """
    candidate = (value or "").strip().lower()
    if candidate in VALID_PORTALS:
        return candidate
    default = SAMLConstants.DEFAULT_PORTAL
    return default if default in VALID_PORTALS else PORTAL_CLIENT


def callback_url_for(portal: str) -> str:
    """Look up a portal's callback URL from the allow-list."""
    if portal == PORTAL_ADMIN:
        return SAMLConstants.ADMIN_FRONTEND_CALLBACK_URL or ""
    return SAMLConstants.CLIENT_FRONTEND_CALLBACK_URL or ""


def user_allowed_in_portal(user, portal: str) -> bool:
    """
    Decide whether a user may enter the portal they signed in from.

    For password login this boundary is implicit: /auth/login/ binds against
    the customer AD tree and /auth/admin/login/ against the admin AD tree, so
    which tree you can authenticate against decides which portal you reach.

    SAML has a single IdP and a single ACS, so that boundary disappears and
    has to be restored explicitly here - otherwise a tenant completing SSO
    from the admin portal would receive a valid admin-portal token pair.

    Mirrors the role derivation in UserDetailSerializer, which the frontend
    reads to pick a dashboard: any admin flag wins over is_tenant. A user
    carrying both must therefore be refused the client portal, or the backend
    would mint a token pair that the frontend then rejects - tokens issued to
    someone who cannot use them is exactly the split this check exists to
    prevent.
    """
    is_staff = bool(user.is_admin or user.is_super_admin or user.is_read_only)
    if portal == PORTAL_ADMIN:
        return is_staff
    return bool(user.is_tenant) and not is_staff


def _strip_cert(cert: str) -> str:
    """
    Normalise a PEM certificate or key for python3-saml.

    Values arrive through environment variables, where newlines are commonly
    escaped as "\\n" and PEM headers may or may not be present. python3-saml
    wants the bare base64 body for certificates, so headers are dropped.
    """
    if not cert:
        return ""
    cert = cert.replace("\\n", "\n")
    lines = [
        line.strip()
        for line in cert.splitlines()
        if line.strip() and "-----" not in line
    ]
    return "".join(lines)


def _private_key(key: str) -> str:
    """Private keys keep their PEM envelope; only escaped newlines are fixed."""
    if not key:
        return ""
    return key.replace("\\n", "\n").strip()


def build_saml_settings() -> dict:
    """
    Assemble the python3-saml settings dict from SAMLConstants.

    Security choices, and why:
      - wantAssertionsSigned / wantMessagesSigned: the assertion is the only
        thing standing between a caller and a portal session, so its origin
        must be proven. Encryption alone proves confidentiality, not origin.
      - rejectDeprecatedAlgorithm: refuses SHA-1 signatures.
      - authnRequestsSigned: driven by the IdP's WantAuthnRequestsSigned flag,
        which FortiAuthenticator publishes in its metadata.
      - NameID format is "unspecified" to match the IdP; identity is taken
        from the attribute statement, not the Subject.
    """
    sp_cert = _strip_cert(SAMLConstants.SP_X509_CERT)
    sp_key = _private_key(SAMLConstants.SP_PRIVATE_KEY)

    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": SAMLConstants.SP_ENTITY_ID,
            "assertionConsumerService": {
                "url": SAMLConstants.SP_ACS_URL,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            # No singleLogoutService: SLO is out of scope for phase one.
            "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified",
            "x509cert": sp_cert,
            "privateKey": sp_key,
        },
        "idp": {
            "entityId": SAMLConstants.IDP_ENTITY_ID,
            "singleSignOnService": {
                "url": SAMLConstants.IDP_SSO_URL,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": _strip_cert(SAMLConstants.IDP_X509_CERT),
        },
        "security": {
            "nameIdEncrypted": False,
            "authnRequestsSigned": SAMLConstants.AUTHN_REQUESTS_SIGNED,
            "logoutRequestSigned": False,
            "logoutResponseSigned": False,
            "signMetadata": False,
            "wantMessagesSigned": False,
            "wantAssertionsSigned": True,
            "wantAssertionsEncrypted": SAMLConstants.WANT_ASSERTIONS_ENCRYPTED,
            "wantNameId": False,
            "wantNameIdEncrypted": False,
            "requestedAuthnContext": False,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
            "rejectDeprecatedAlgorithm": True,
        },
    }


def prepare_django_request(request) -> dict:
    """
    Adapt a Django request into the dict python3-saml expects.

    The host and port are taken from SP_ACS_URL rather than from the incoming
    request, because the assertion's Destination and Audience are validated
    against the SP's published URLs. Behind a reverse proxy the request's own
    host and scheme reflect the internal hop, not what the IdP was told, and
    trusting them would either break validation or make it spoofable.
    """
    parsed = urlparse(SAMLConstants.SP_ACS_URL or "")
    https = "on" if parsed.scheme == "https" else "off"
    port = str(parsed.port) if parsed.port else ("443" if https == "on" else "80")

    return {
        "https": https,
        "http_host": parsed.hostname or request.get_host(),
        "server_port": port,
        "script_name": request.path,
        "get_data": request.GET.copy(),
        "post_data": request.POST.copy(),
    }


def init_saml_auth(request) -> "OneLogin_Saml2_Auth":
    return OneLogin_Saml2_Auth(prepare_django_request(request), build_saml_settings())


def get_sp_metadata() -> str:
    """
    Render this SP's metadata XML.

    Handed to the du team so they can configure the Service Provider entry on
    FortiAuthenticator. It carries our public encryption certificate; the
    private key never leaves this deployment.
    """
    settings = OneLogin_Saml2_Settings(
        build_saml_settings(), sp_validation_only=True
    )
    # python3-saml defaults validUntil to two days out, which is shorter than
    # the turnaround for an IdP administrator to receive a file by email and
    # import it - our first attempt expired before the du team got to it, and
    # FortiAuthenticator rejects expired metadata. A year is long enough that
    # the file stays usable, and the endpoint regenerates it on every request
    # anyway.
    valid_until = datetime.now(timezone.utc) + timedelta(days=365)
    metadata = settings.get_sp_metadata(valid_until=valid_until)
    errors = settings.validate_metadata(metadata)
    if errors:
        raise ValueError(f"Generated SP metadata is invalid: {errors}")
    if isinstance(metadata, bytes):
        metadata = metadata.decode("utf-8")
    # Some metadata importers require the declaration before they will parse
    # the document at all.
    if not metadata.lstrip().startswith("<?xml"):
        metadata = XML_DECLARATION + metadata
    return metadata


def _first(attributes: dict, name: str):
    """
    Read one assertion attribute.

    python3-saml returns every attribute as a list because SAML attributes are
    multi-valued; all the ones we read are single-valued in practice.
    """
    values = attributes.get(name) or []
    if isinstance(values, (list, tuple)):
        return values[0] if values else None
    return values


def extract_identity(auth: "OneLogin_Saml2_Auth") -> dict:
    """
    Pull the identity out of a validated assertion.

    Only the username is required. mail / givenName / sn are read when the IdP
    releases them, but the portal does not auto-provision users, so their
    absence is not an error - the account must already exist either way.
    """
    attributes = auth.get_attributes() or {}

    username = _first(attributes, SAMLConstants.USERNAME_ATTRIBUTE)
    if not username:
        # Fall back to the NameID. The IdP publishes "unspecified" as its only
        # NameID format, so this is a safety net rather than the usual path.
        username = auth.get_nameid()

    return {
        "username": (username or "").strip(),
        "email": _first(attributes, SAMLConstants.EMAIL_ATTRIBUTE),
        "first_name": _first(attributes, SAMLConstants.FIRST_NAME_ATTRIBUTE),
        "last_name": _first(attributes, SAMLConstants.LAST_NAME_ATTRIBUTE),
        "attribute_names": sorted(attributes.keys()),
    }
