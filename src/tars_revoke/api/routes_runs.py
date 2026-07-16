from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from tars_revoke.errors import ValidationError

from .dependencies import RunControl, get_run_control
from .schemas import DemoStartRequest, RunSnapshot
from .snapshot import build_snapshot

router = APIRouter(prefix="/api/runs", tags=["runs"])


def resolve_run_id(control: RunControl, run_id: str) -> str:
    resolved = control.current_run_id if run_id == "current" else run_id
    if not resolved:
        raise HTTPException(status_code=404, detail="no TARS REVOKE run has started")
    return resolved


def snapshot_for(control: RunControl, run_id: str) -> RunSnapshot:
    resolved = resolve_run_id(control, run_id)
    try:
        return build_snapshot(control.store_for(resolved), resolved)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"run {resolved} was not found") from exc


@router.get("/{run_id}", response_model=RunSnapshot)
async def get_run(
    run_id: str,
    control: Annotated[RunControl, Depends(get_run_control)],
) -> RunSnapshot:
    return snapshot_for(control, run_id)


@router.post("/demo", response_model=RunSnapshot, status_code=202)
async def start_demo(
    request: DemoStartRequest,
    control: Annotated[RunControl, Depends(get_run_control)],
) -> RunSnapshot:
    try:
        run_id = await control.start_demo(
            scenario=request.scenario,
            live_codex=request.live_codex,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return snapshot_for(control, run_id)


@router.post("/{run_id}/verify", response_model=RunSnapshot)
async def verify_run(
    run_id: str,
    control: Annotated[RunControl, Depends(get_run_control)],
) -> RunSnapshot:
    resolved = resolve_run_id(control, run_id)
    try:
        await control.verify(resolved)
    except (KeyError, FileNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return snapshot_for(control, resolved)
