from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from tars_revoke.clock import Clock, SystemClock
from tars_revoke.domain.canonical import canonical_bytes, sha256_digest
from tars_revoke.domain.models import ArtifactRef
from tars_revoke.errors import IntegrityError


class ArtifactStore:
    """Immutable SHA-256-addressed artifact storage."""

    def __init__(self, root: str | Path, *, clock: Clock | None = None):
        self.root = Path(root).expanduser().resolve()
        self.clock = clock or SystemClock()
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, digest: str) -> Path:
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("artifact digest must be lowercase SHA-256")
        return self.root / digest[:2] / digest[2:]

    def put_bytes(
        self,
        content: bytes,
        *,
        media_type: str = "application/octet-stream",
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRef:
        digest = sha256_digest(content)
        destination = self.path_for(digest)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            self.verify(digest)
        else:
            descriptor, temp_name = tempfile.mkstemp(prefix=".artifact-", dir=destination.parent)
            temp = Path(temp_name)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temp, 0o440)
                try:
                    os.link(temp, destination)
                except FileExistsError:
                    self.verify(digest)
                finally:
                    temp.unlink(missing_ok=True)
            except BaseException:
                temp.unlink(missing_ok=True)
                raise
        relative_path = destination.relative_to(self.root).as_posix()
        return ArtifactRef(
            digest=digest,
            size=len(content),
            media_type=media_type,
            relative_path=relative_path,
            created_at=self.clock.utc_now(),
            metadata=metadata or {},
        )

    def put_text(
        self,
        content: str,
        *,
        media_type: str = "text/plain; charset=utf-8",
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRef:
        return self.put_bytes(content.encode("utf-8"), media_type=media_type, metadata=metadata)

    def put_json(self, value: Any, *, metadata: dict[str, Any] | None = None) -> ArtifactRef:
        return self.put_bytes(
            canonical_bytes(value),
            media_type="application/json",
            metadata=metadata,
        )

    def put_file(
        self,
        path: str | Path,
        *,
        media_type: str = "application/octet-stream",
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRef:
        source = Path(path)
        if not source.is_file() or source.is_symlink():
            raise ValueError("artifact source must be a regular non-symlink file")
        return self.put_bytes(source.read_bytes(), media_type=media_type, metadata=metadata)

    def get_bytes(self, digest: str) -> bytes:
        path = self.path_for(digest)
        content = path.read_bytes()
        actual = sha256_digest(content)
        if actual != digest:
            raise IntegrityError(f"artifact {digest} was modified (actual {actual})")
        return content

    def exists(self, digest: str) -> bool:
        return self.path_for(digest).is_file()

    def verify(self, digest: str) -> None:
        self.get_bytes(digest)
