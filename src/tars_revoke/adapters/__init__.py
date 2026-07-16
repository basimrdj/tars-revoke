"""I/O adapters for TARS REVOKE.

Adapters perform effects and report what happened.  They deliberately do not
decide whether an effect is authorized; that belongs to the services layer.
"""

from .base import (
    AdapterHealth,
    AgentAdapter,
    EvidenceSourceAdapter,
    GitEffectAdapter,
    MigrationEffectAdapter,
    ProcessAdapter,
)

__all__ = [
    "AdapterHealth",
    "AgentAdapter",
    "EvidenceSourceAdapter",
    "GitEffectAdapter",
    "MigrationEffectAdapter",
    "ProcessAdapter",
]
