from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from tars_revoke.api import create_app
from tars_revoke.config import Settings
from tars_revoke.demo.failures import finalize_failed_run
from tars_revoke.demo.manager import RunManager
from tars_revoke.domain.enums import RunState
from tars_revoke.domain.models import Run
from tars_revoke.persistence.store import Store

NOW = datetime(2026, 7, 14, tzinfo=timezone.utc)


class FakeRunControl:
    def __init__(self, store: Store) -> None:
        self.store = store
        self._current = "run-api"

    @property
    def current_run_id(self) -> str | None:
        return self._current

    async def start_demo(self, *, scenario: str, live_codex: bool) -> str:
        assert scenario == "external-schema-v2"
        assert live_codex
        return self._current

    def store_for(self, run_id: str) -> Store:
        if run_id != self._current:
            raise KeyError(run_id)
        return self.store

    async def verify(self, run_id: str) -> None:
        if run_id != self._current:
            raise KeyError(run_id)


def test_api_serves_authoritative_empty_run_and_demo_control(tmp_path: Path) -> None:
    store = Store(tmp_path / "api.sqlite")
    store.create_run(
        Run(
            id="run-api",
            name="API test",
            state=RunState.RUNNING,
            root_path=str(tmp_path),
            created_at=NOW,
            updated_at=NOW,
            metadata={"scenario": "external-schema-v2"},
        )
    )
    app = create_app(FakeRunControl(store))

    with TestClient(app) as client:
        health = client.get("/api/health")
        snapshot = client.get("/api/runs/current")
        started = client.post(
            "/api/runs/demo",
            json={"scenario": "external-schema-v2", "live_codex": True},
        )
        verified = client.post("/api/runs/run-api/verify")
        missing_stream = client.get("/api/runs/missing/stream")

    assert health.json()["ok"] is True
    assert snapshot.status_code == 200
    assert snapshot.json()["run"]["sequence"] == 1
    assert snapshot.json()["run"]["execution_mode"] == "unknown"
    assert snapshot.json()["agents"] == []
    assert started.status_code == 202
    assert verified.status_code == 200
    assert missing_stream.status_code == 404


def test_spa_fallback_never_masks_an_unknown_api_route(tmp_path: Path) -> None:
    store = Store(tmp_path / "api.sqlite")
    static_root = tmp_path / "dist"
    static_root.mkdir()
    (static_root / "index.html").write_text("<main>operator console</main>", encoding="utf-8")
    app = create_app(FakeRunControl(store), frontend_dir=static_root)

    with TestClient(app) as client:
        api_response = client.get("/api/does-not-exist")
        client_route = client.get("/runs/current")

    assert api_response.status_code == 404
    assert api_response.json() == {"detail": "API route not found"}
    assert client_route.status_code == 200
    assert "operator console" in client_route.text


def test_failed_run_snapshot_is_durable_and_verify_returns_conflict(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    artifact_root = data_dir / "runs" / "run-failed" / "artifacts" / "run-failed"
    artifact_root.mkdir(parents=True)
    store = Store(artifact_root / "state.sqlite")
    store.create_run(
        Run(
            id="run-failed",
            name="Failed API run",
            state=RunState.RUNNING,
            root_path=str(artifact_root.parent),
            created_at=NOW,
            updated_at=NOW,
            metadata={"scenario": "external-schema-v2", "repair_provider": "scripted"},
        )
    )
    finalize_failed_run(
        store=store,
        run_id="run-failed",
        artifact_root=artifact_root,
        error=RuntimeError("experiment candidate violated the command grammar"),
    )
    app = create_app(RunManager(Settings(data_dir=data_dir)))

    with TestClient(app) as client:
        snapshot = client.get("/api/runs/current")
        verification = client.post("/api/runs/run-failed/verify")

    assert snapshot.status_code == 200
    body = snapshot.json()
    assert body["run"]["status"] == "FAILED"
    assert body["failure"]["message"] == "experiment candidate violated the command grammar"
    assert body["receipt"]["status"] == "INVALID"
    assert verification.status_code == 409
    assert "run failed" in verification.json()["detail"]
