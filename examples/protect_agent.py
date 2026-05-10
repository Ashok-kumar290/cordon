"""Protect a coding-agent step function with Cordon.

Shows the ``@guard.protect`` decorator pattern. Any agent step that
receives a proposed ``Action`` can be wrapped so dangerous actions raise
``BlockedAction`` before your executor ever sees them.
"""

from cordon import Action, Guard
from cordon.core.guard import BlockedAction

guard = Guard.strict()


@guard.protect
def run_shell(action: Action) -> str:
    """Pretend-execute a shell command. In real code this would call subprocess."""
    return f"[executed] {action.command}"


def main() -> None:
    safe = Action(kind="shell", command="echo hello world")
    attack = Action(
        kind="shell",
        command="pip install -r requirements.txt",
        changes={"requirements.txt": "reqeusts==2.31.0\n"},
    )

    print(run_shell(safe))

    try:
        print(run_shell(attack))
    except BlockedAction as e:
        print(f"[blocked] {e.verdict.top_reason()}")


if __name__ == "__main__":
    main()
