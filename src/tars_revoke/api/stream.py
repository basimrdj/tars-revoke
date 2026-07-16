from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from .dependencies import RunControl, get_run_control
from .routes_runs import resolve_run_id, snapshot_for

router = APIRouter(prefix="/api/runs", tags=["stream"])


async def _snapshot_events(
    request: Request,
    control: RunControl,
    run_id: str,
    after: int,
) -> AsyncIterator[str]:
    sequence = max(0, after)
    heartbeat_ticks = 0
    while not await request.is_disconnected():
        snapshot = snapshot_for(control, run_id)
        if snapshot.run.sequence > sequence:
            sequence = snapshot.run.sequence
            yield (f"id: {sequence}\nevent: snapshot\ndata: {snapshot.model_dump_json()}\n\n")
            heartbeat_ticks = 0
        else:
            heartbeat_ticks += 1
            if heartbeat_ticks >= 40:
                yield ": keep-alive\n\n"
                heartbeat_ticks = 0
        await asyncio.sleep(0.25)


@router.get("/{run_id}/stream")
async def stream_run(
    request: Request,
    run_id: str,
    control: Annotated[RunControl, Depends(get_run_control)],
    after: Annotated[int, Query(ge=0)] = 0,
) -> StreamingResponse:
    resolved = resolve_run_id(control, run_id)
    try:
        control.store_for(resolved)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"run {resolved} was not found") from exc
    return StreamingResponse(
        _snapshot_events(request, control, resolved, after),
        media_type="text/event-stream",
        headers={
            "cache-control": "no-cache",
            "x-accel-buffering": "no",
        },
    )
