from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .dependencies import RunControl
from .routes_runs import router as runs_router
from .stream import router as stream_router


def create_app(
    run_control: RunControl,
    *,
    frontend_dir: Path | None = None,
    title: str = "TARS REVOKE",
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        start = getattr(run_control, "start", None)
        if start is not None:
            result = start()
            if hasattr(result, "__await__"):
                await result
        try:
            yield
        finally:
            close = getattr(run_control, "close", None)
            if close is not None:
                result = close()
                if hasattr(result, "__await__"):
                    await result

    app = FastAPI(
        title=title,
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.state.run_control = run_control
    app.include_router(stream_router)
    app.include_router(runs_router)

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {
            "ok": True,
            "product": "TARS REVOKE",
            "current_run_id": run_control.current_run_id,
        }

    static_root = frontend_dir.resolve() if frontend_dir and frontend_dir.is_dir() else None
    if static_root is not None:
        assets = static_root / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        async def frontend(path: str) -> FileResponse:
            if path == "api" or path.startswith("api/"):
                raise HTTPException(status_code=404, detail="API route not found")
            candidate = (static_root / path).resolve()
            if candidate.is_file() and candidate.is_relative_to(static_root):
                return FileResponse(candidate)
            return FileResponse(static_root / "index.html")

    return app
