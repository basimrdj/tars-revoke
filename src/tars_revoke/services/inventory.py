from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath

from tars_revoke.errors import IntegrityError, ValidationError


class ChangeKind(str, Enum):
    CREATED = "CREATED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"


@dataclass(frozen=True)
class InventoryChange:
    path: str
    kind: ChangeKind
    before_hash: str | None
    after_hash: str | None


@dataclass(frozen=True)
class InventoryReconciliation:
    changes: tuple[InventoryChange, ...]
    attributed_paths: tuple[str, ...]
    unattributed_paths: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return not self.unattributed_paths

    def require_complete(self) -> None:
        if self.unattributed_paths:
            joined = ", ".join(self.unattributed_paths)
            raise IntegrityError(f"unattributed durable effects: {joined}")


class EffectInventory:
    """Reconcile content-addressed worktree snapshots deterministically."""

    @staticmethod
    def diff(
        before: Mapping[str, str],
        after: Mapping[str, str],
    ) -> tuple[InventoryChange, ...]:
        normalized_before = EffectInventory._normalize_snapshot(before)
        normalized_after = EffectInventory._normalize_snapshot(after)
        changes: list[InventoryChange] = []
        for path in sorted(set(normalized_before) | set(normalized_after)):
            before_hash = normalized_before.get(path)
            after_hash = normalized_after.get(path)
            if before_hash == after_hash:
                continue
            if before_hash is None:
                kind = ChangeKind.CREATED
            elif after_hash is None:
                kind = ChangeKind.DELETED
            else:
                kind = ChangeKind.MODIFIED
            changes.append(
                InventoryChange(
                    path=path,
                    kind=kind,
                    before_hash=before_hash,
                    after_hash=after_hash,
                )
            )
        return tuple(changes)

    @staticmethod
    def reconcile(
        before: Mapping[str, str],
        after: Mapping[str, str],
        *,
        attributed_paths: set[str] | frozenset[str],
    ) -> InventoryReconciliation:
        changes = EffectInventory.diff(before, after)
        normalized_attributed = {
            EffectInventory._normalize_path(path) for path in attributed_paths
        }
        changed_paths = {change.path for change in changes}
        return InventoryReconciliation(
            changes=changes,
            attributed_paths=tuple(sorted(changed_paths & normalized_attributed)),
            unattributed_paths=tuple(sorted(changed_paths - normalized_attributed)),
        )

    @staticmethod
    def _normalize_snapshot(snapshot: Mapping[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for path, digest in snapshot.items():
            normalized_path = EffectInventory._normalize_path(path)
            if not digest:
                raise ValidationError(f"empty content digest for {normalized_path}")
            if normalized_path in normalized and normalized[normalized_path] != digest:
                raise ValidationError(f"duplicate normalized path: {normalized_path}")
            normalized[normalized_path] = str(digest)
        return normalized

    @staticmethod
    def _normalize_path(path: str) -> str:
        candidate = PurePosixPath(str(path).replace("\\", "/"))
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValidationError(f"inventory path must be relative and contained: {path}")
        normalized = candidate.as_posix()
        if normalized in {"", "."}:
            raise ValidationError("inventory path must name a file")
        return normalized
