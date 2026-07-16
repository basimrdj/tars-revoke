from __future__ import annotations


class RevokeError(Exception):
    """Base error for expected TARS REVOKE failures."""


class ValidationError(RevokeError):
    pass


class TransitionError(RevokeError):
    pass


class AuthorizationError(RevokeError):
    pass


class StaleWarrantError(AuthorizationError):
    pass


class IntegrityError(RevokeError):
    pass


class AdapterError(RevokeError):
    pass


class CompensationError(RevokeError):
    pass
