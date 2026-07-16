"""HTTP and event-stream surface for the TARS REVOKE control plane."""

from .app import create_app

__all__ = ["create_app"]
