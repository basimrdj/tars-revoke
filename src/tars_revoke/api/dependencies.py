from __future__ import annotations

from typing import Protocol, cast

from fastapi import Request

from tars_revoke.persistence.store import Store


class RunControl(Protocol):
    @property
    def current_run_id(self) -> str | None: ...

    async def start_demo(self, *, scenario: str, live_codex: bool) -> str: ...

    def store_for(self, run_id: str) -> Store: ...

    async def verify(self, run_id: str) -> object: ...


def get_run_control(request: Request) -> RunControl:
    return cast(RunControl, request.app.state.run_control)
