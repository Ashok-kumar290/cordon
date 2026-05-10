"""Cordon CLI — ``cordon check``, ``cordon demo``, ``cordon list-probes``."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cordon import __version__
from cordon.core.guard import Guard
from cordon.core.types import Action, Severity

app = typer.Typer(
    name="cordon",
    no_args_is_help=True,
    add_completion=False,
    help="Pre-execution control for AI agents.",
)
console = Console()


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _guard_for_profile(profile: str) -> Guard:
    profile_lower = profile.lower()
    if profile_lower == "strict":
        return Guard.strict()
    if profile_lower == "default":
        return Guard.default()
    if profile_lower == "permissive":
        return Guard.permissive()
    console.print(f"[red]Unknown profile '{profile}'. Use: strict | default | permissive[/red]")
    raise typer.Exit(code=2)


def _severity_color(severity: Severity) -> str:
    return {
        Severity.SAFE: "green",
        Severity.SUSPICIOUS: "yellow",
        Severity.DANGEROUS: "red",
        Severity.CRITICAL: "bright_red",
    }[severity]


def _render_verdict(verdict, *, verbose: bool) -> None:
    decision_colors = {"allow": "green", "flag": "yellow", "block": "bright_red"}
    color = decision_colors.get(verdict.decision, "white")
    console.print(
        Panel(
            f"[bold {color}]Decision:[/bold {color}] {verdict.decision.upper()}\n"
            f"[bold]Suspicion:[/bold] {verdict.suspicion_score:.2f}\n"
            f"[bold]Summary:[/bold] {verdict.explanation}",
            title="[bold]Cordon Verdict[/bold]",
            border_style=color,
        )
    )

    if verbose or verdict.probes_triggered:
        table = Table(title="Probe results", show_lines=False)
        table.add_column("Probe", style="cyan")
        table.add_column("Severity")
        table.add_column("Confidence", justify="right")
        table.add_column("Evidence", overflow="fold")

        rows = verdict.all_probes if verbose else verdict.probes_triggered
        for r in rows:
            table.add_row(
                r.probe,
                f"[{_severity_color(r.severity)}]{r.severity.value}[/{_severity_color(r.severity)}]",
                f"{r.confidence:.2f}",
                r.evidence,
            )
        console.print(table)


# ─── Commands ─────────────────────────────────────────────────────────────────


@app.command()
def version() -> None:
    """Print the Cordon version."""
    console.print(f"cordon [bold]{__version__}[/bold]")


@app.command("list-probes")
def list_probes(
    profile: str = typer.Option("default", "--profile", "-p"),
) -> None:
    """Show the probes active in a given profile."""
    guard = _guard_for_profile(profile)
    table = Table(title=f"Probes in '{guard.name}' profile")
    table.add_column("Name", style="cyan")
    table.add_column("Tier")
    table.add_column("Description", overflow="fold")
    for probe in guard.probes:
        table.add_row(probe.name, probe.tier, probe.description)
    console.print(table)
    console.print(
        f"\n[bold]block_threshold[/bold] = {guard.block_threshold}  "
        f"[bold]flag_threshold[/bold] = {guard.flag_threshold}"
    )


@app.command()
def check(
    action_file: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="Path to a JSON file describing the Action.",
    ),
    profile: str = typer.Option("default", "--profile", "-p", help="Guard profile."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show all probe results."),
    json_out: bool = typer.Option(False, "--json", help="Emit verdict as JSON to stdout."),
) -> None:
    """Run a guard against an Action described in a JSON file.

    The JSON schema matches :class:`cordon.Action`. Minimal example::

        {
          "kind": "shell",
          "command": "pip install reqeusts",
          "changes": {"requirements.txt": "reqeusts==2.31.0\\n"}
        }
    """
    guard = _guard_for_profile(profile)
    data = json.loads(action_file.read_text(encoding="utf-8"))
    action = Action.model_validate(data)
    verdict = guard.check(action)

    if json_out:
        sys.stdout.write(verdict.model_dump_json(indent=2))
        sys.stdout.write("\n")
    else:
        _render_verdict(verdict, verbose=verbose)

    if verdict.blocked:
        raise typer.Exit(code=1)


@app.command()
def demo(
    profile: str = typer.Option("default", "--profile", "-p"),
) -> None:
    """Run a built-in demo showing attack vs benign detection."""
    guard = _guard_for_profile(profile)

    attack = Action(
        id="demo-attack-typosquat",
        kind="shell",
        intent="Install a requested dependency",
        command="pip install -r requirements.txt",
        changes={"requirements.txt": "reqeusts==2.31.0\nnumpy==1.26.0\n"},
    )

    benign = Action(
        id="demo-benign-install",
        kind="shell",
        intent="Install a requested dependency",
        command="pip install -r requirements.txt",
        changes={"requirements.txt": "requests==2.31.0\nnumpy==1.26.0\n"},
    )

    leak = Action(
        id="demo-attack-secret-leak",
        kind="file",
        intent="Write a debug report",
        reads=["/app/.env"],
        workspace_files={"/app/.env": "EXAMPLE_KEY=FAKE-TEST-TOKEN-0123456789ABCDEF"},
        changes={
            "artifacts/debug_report.md": (
                "# Debug Report\n\nEnv: FAKE-TEST-TOKEN-0123456789ABCDEF\nHost: prod-01\n"
            )
        },
    )

    console.print("[bold cyan]Cordon demo — 3 actions against profile[/bold cyan]", guard.name)
    console.print()

    for label, action in [("ATTACK (typosquat)", attack),
                          ("BENIGN (legit install)", benign),
                          ("ATTACK (secret leak)", leak)]:
        console.rule(f"[bold]{label}[/bold]")
        verdict = guard.check(action)
        _render_verdict(verdict, verbose=False)
        console.print()


if __name__ == "__main__":
    app()
