from __future__ import annotations

import re
import tarfile
import zipfile
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"release archive check failed: {message}")


def forbidden(name: str) -> bool:
    parts = name.split("/")
    relative = "/".join(parts[1:]) if name.startswith("tars_revoke-") else name
    return any(
        (
            re.fullmatch(r"tars_[^/]+\.py", relative) is not None,
            re.fullmatch(r"test_(apple|llm|local|mlx|tts)[^/]*\.py", relative) is not None,
            relative in {"PLAN.md", "TARS_SOUL.md"},
            relative.startswith("scripts/"),
            relative.startswith("tars_vibevoice/"),
            "/node_modules/" in f"/{relative}",
            "/__pycache__/" in f"/{relative}/",
            relative.endswith(".map"),
        )
    )


def require_suffix(names: set[str], suffix: str) -> None:
    if not any(name.endswith(suffix) for name in names):
        fail(f"missing {suffix}")


def main() -> None:
    dist = Path("dist")
    sdists = sorted(dist.glob("tars_revoke-*.tar.gz"))
    wheels = sorted(dist.glob("tars_revoke-*.whl"))
    if len(sdists) != 1 or len(wheels) != 1:
        fail("expected exactly one sdist and one wheel")

    with tarfile.open(sdists[0], "r:gz") as archive:
        sdist_names = {member.name for member in archive.getmembers()}
    with zipfile.ZipFile(wheels[0]) as archive:
        wheel_names = set(archive.namelist())

    bad = sorted(name for name in sdist_names | wheel_names if forbidden(name))
    if bad:
        fail("forbidden legacy/generated paths: " + ", ".join(bad[:10]))

    for suffix in (
        "/README.md",
        "/LICENSE",
        "/uv.lock",
        "/web/dist/index.html",
        "/docs/revoke/PRODUCT_SPEC.md",
    ):
        require_suffix(sdist_names, suffix)
    for suffix in (
        "tars_revoke/persistence/schema.sql",
        "tars_revoke/demo/fixture_template/scripts/contract_probe.py",
        "tars_revoke/web_dist/index.html",
    ):
        require_suffix(wheel_names, suffix)
    if not any(
        name.startswith("tars_revoke/web_dist/assets/") and name.endswith(".js")
        for name in wheel_names
    ):
        fail("wheel is missing the compiled operator-console JavaScript")
    if not any(
        name.startswith("tars_revoke/web_dist/assets/") and name.endswith(".css")
        for name in wheel_names
    ):
        fail("wheel is missing the compiled operator-console CSS")

    print(
        f"release archives verified: {len(sdist_names)} sdist entries, "
        f"{len(wheel_names)} wheel entries"
    )


if __name__ == "__main__":
    main()
