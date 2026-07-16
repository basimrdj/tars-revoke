from __future__ import annotations

import asyncio
import json
import shutil
import sqlite3
import subprocess
import sys
from collections.abc import Coroutine
from pathlib import Path
from typing import Annotated, Any, TypeVar

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from tars_revoke.adapters.codex import CodexCLIAdapter
from tars_revoke.adapters.processes import AsyncProcessRunner
from tars_revoke.api.schemas import DoctorCheck, DoctorReport
from tars_revoke.config import Settings, load_settings
from tars_revoke.demo.verifier import find_artifact_root, verify_bundle

app = typer.Typer(
    name="tars-revoke",
    help="Continuous evidence-backed authorization for coding agents.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
console = Console()
ResultT = TypeVar("ResultT")


def _frontend_distribution(package_root: Path | None = None) -> Path:
    root = package_root or Path(__file__).resolve().parent
    packaged = root / "web_dist"
    if (packaged / "index.html").is_file():
        return packaged
    return root.parents[1] / "web" / "dist"


def _run(coroutine: Coroutine[Any, Any, ResultT]) -> ResultT:
    return asyncio.run(coroutine)


async def _doctor_report(settings: Settings) -> DoctorReport:
    checks: list[DoctorCheck] = []
    checks.append(
        DoctorCheck(
            name="python",
            ok=sys.version_info >= (3, 10),
            detail=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        )
    )
    checks.append(
        DoctorCheck(
            name="sqlite",
            ok=sqlite3.sqlite_version_info >= (3, 35),
            detail=sqlite3.sqlite_version,
        )
    )

    git = shutil.which("git")
    if git is None:
        checks.append(DoctorCheck(name="git", ok=False, detail="git not found on PATH"))
    else:
        result = subprocess.run(
            (git, "--version"),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        checks.append(
            DoctorCheck(
                name="git",
                ok=result.returncode == 0,
                detail=(result.stdout or result.stderr).strip(),
            )
        )

    cwd = Path.cwd().resolve()
    runner = AsyncProcessRunner([cwd])
    try:
        executable = await CodexCLIAdapter.discover_executable(
            process_runner=runner,
            probe_cwd=cwd,
            explicit_bin=settings.codex_bin,
        )
        checks.append(
            DoctorCheck(
                name="codex",
                ok=True,
                detail=f"{executable.version} · {executable.path}",
            )
        )
    except Exception as exc:
        checks.append(DoctorCheck(name="codex", ok=False, detail=str(exc)))

    web_dist = _frontend_distribution() / "index.html"
    checks.append(
        DoctorCheck(
            name="web-build",
            ok=web_dist.is_file(),
            detail=str(web_dist) if web_dist.is_file() else "run `make web-build`",
        )
    )
    critical = {"python", "sqlite", "git", "codex"}
    ok = all(check.ok for check in checks if check.name in critical)
    return DoctorReport(ok=ok, checks=tuple(checks))


@app.command()
def doctor(
    as_json: Annotated[bool, typer.Option("--json", help="Emit machine-readable JSON.")] = False,
) -> None:
    """Check the exact local capabilities required by the live demo."""

    report = _run(_doctor_report(load_settings()))
    if as_json:
        console.print_json(report.model_dump_json())
    else:
        table = Table(title="TARS REVOKE doctor", show_header=True)
        table.add_column("Check")
        table.add_column("Result")
        table.add_column("Detail", overflow="fold")
        for check in report.checks:
            table.add_row(check.name, "PASS" if check.ok else "FAIL", check.detail)
        console.print(table)
    if not report.ok:
        raise typer.Exit(code=1)


@app.command()
def demo(
    scenario: Annotated[str, typer.Option("--scenario")] = "external-schema-v2",
    live_codex: Annotated[
        bool,
        typer.Option(
            "--live-codex/--scripted",
            help=(
                "Use real Codex sessions; scripted mode is visibly labelled and never counts "
                "as live proof."
            ),
        ),
    ] = False,
    output_root: Annotated[Path | None, typer.Option("--output-root")] = None,
) -> None:
    """Run the canonical two-agent selective-revocation scenario."""

    if scenario != "external-schema-v2":
        raise typer.BadParameter(
            "only external-schema-v2 is currently defined", param_hint="scenario"
        )
    settings = load_settings()
    root = (output_root or settings.data_dir / "runs").expanduser().resolve()

    async def execute() -> tuple[Any, Any]:
        from tars_revoke.demo.failures import finalize_without_masking
        from tars_revoke.demo.scenario import CanonicalScenario

        handle = await CanonicalScenario.prepare(
            root,
            live_codex=live_codex,
            codex_model=settings.codex_model,
            codex_bin=settings.codex_bin,
            codex_timeout_seconds=settings.codex_timeout_seconds,
        )
        source_error: BaseException | None = None
        try:
            result = await handle.run()
            artifact_root = getattr(result, "artifact_root", handle.fixture.artifacts_root)
            verification = verify_bundle(
                artifact_root,
                required_requirement_ids=handle.proof_requirements,
            )
            return result, verification
        except BaseException as exc:
            source_error = exc
            # This boundary is deliberately inside the active exception handler: any
            # finalization failure is secondary and the canonical source error survives.
            finalize_without_masking(
                store=handle.store,
                run_id=handle.fixture.run_id,
                artifact_root=handle.fixture.artifacts_root,
                error=exc,
            )
            raise
        finally:
            try:
                await handle.close()
            except BaseException as close_error:
                if source_error is None:
                    finalize_without_masking(
                        store=handle.store,
                        run_id=handle.fixture.run_id,
                        artifact_root=handle.fixture.artifacts_root,
                        error=close_error,
                    )
                    raise

    try:
        result, verification = _run(execute())
    except Exception as exc:
        from tars_revoke.demo.failures import sanitize_failure_text

        console.print(f"[red]Demo failed:[/red] {sanitize_failure_text(exc)}")
        raise typer.Exit(code=1) from exc
    artifact_root = getattr(result, "artifact_root", None)
    console.print("[green]Canonical scenario completed and independently verified.[/green]")
    console.print(f"Run: [bold]{verification.run_id}[/bold]")
    console.print(f"Effects revoked: {', '.join(verification.affected_effect_ids)}")
    if artifact_root is not None:
        console.print(f"Proof bundle: {artifact_root}")
    if not live_codex:
        console.print(
            "[yellow]Scripted mode is protocol proof only; it does not satisfy live Codex "
            "requirements.[/yellow]"
        )


@app.command()
def verify(
    target: Annotated[Path, typer.Argument(help="Proof bundle directory or receipt.json.")],
    strict: Annotated[bool, typer.Option("--strict/--core")] = True,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Recompute receipt, artifact, event-chain, causal, Git, and test proofs."""

    try:
        report = verify_bundle(find_artifact_root(target), strict=strict)
    except Exception as exc:
        console.print(f"[red]Verification failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if as_json:
        console.print_json(json.dumps(report.__dict__, default=list, sort_keys=True))
    else:
        console.print(f"[green]VERIFIED[/green] {report.receipt_digest}")
        console.print(f"Run {report.run_id} · case {report.case_id}")
        console.print(f"Requirements: {', '.join(report.checked_requirements)}")


@app.command()
def serve(
    host: Annotated[str | None, typer.Option("--host")] = None,
    port: Annotated[int | None, typer.Option("--port", min=1024, max=65535)] = None,
) -> None:
    """Serve the API, event stream, and built operator console."""

    from tars_revoke.api import create_app
    from tars_revoke.demo.manager import RunManager

    defaults = load_settings()
    settings = load_settings(
        bind_host=host or defaults.bind_host,
        bind_port=port or defaults.bind_port,
    )
    manager = RunManager(settings)
    frontend = _frontend_distribution()
    application = create_app(manager, frontend_dir=frontend)
    uvicorn.run(application, host=settings.bind_host, port=settings.bind_port, log_level="info")


@app.command()
def bench(
    suite: Annotated[str, typer.Option("--suite")] = "RevokeBench-20",
    output_root: Annotated[Path | None, typer.Option("--output-root")] = None,
) -> None:
    """Run the repeatable safety/selectivity benchmark suite."""

    if suite not in {"RevokeBench-20", "CrashBench-11"}:
        raise typer.BadParameter("unknown benchmark suite", param_hint="suite")
    settings = load_settings()
    resolved_output = (output_root or settings.data_dir / "benchmarks").resolve()
    if suite == "CrashBench-11":
        from tars_revoke.demo.crashbench import run_crashbench_suite

        report = _run(run_crashbench_suite(output_root=resolved_output, suite=suite))
    else:
        from tars_revoke.demo.benchmarks import run_benchmark_suite

        report = _run(
            run_benchmark_suite(
                output_root=resolved_output,
                suite=suite,
            )
        )
    console.print_json(json.dumps(report, sort_keys=True))
    if report.get("passed") is not True:
        raise typer.Exit(code=1)


@app.command("attest-release")
def attest_release(
    qualification_journal: Annotated[
        Path,
        typer.Option("--qualification-journal", help="Passed clean-clone journal.json."),
    ],
    crash_report: Annotated[
        Path,
        typer.Option("--crash-report", help="CrashBench-11 report.json."),
    ],
    benchmark_report: Annotated[
        Path,
        typer.Option("--benchmark-report", help="RevokeBench-20 report.json."),
    ],
    output_root: Annotated[
        Path,
        typer.Option("--output-root", help="New directory for the portable R01-R20 proof."),
    ],
) -> None:
    """Build and independently verify the portable strict release attestation."""

    from tars_revoke.demo.release import build_release_attestation

    result = build_release_attestation(
        qualification_journal_path=qualification_journal,
        crash_report_path=crash_report,
        benchmark_report_path=benchmark_report,
        output_root=output_root,
    )
    console.print("[green]Strict R-01 through R-20 release attestation verified.[/green]")
    console.print(f"Release proof: [bold]{result.artifact_root}[/bold]")
    console.print(f"Attestation: {result.receipt_path}")


if __name__ == "__main__":
    app()
