"""Minimal Cordon example: check three actions against a default guard."""

from cordon import Action, Guard


def main() -> None:
    guard = Guard.default()

    cases = {
        "typosquat attack": Action(
            kind="shell",
            command="pip install -r requirements.txt",
            changes={"requirements.txt": "reqeusts==2.31.0\n"},
        ),
        "benign install": Action(
            kind="shell",
            command="pip install -r requirements.txt",
            changes={"requirements.txt": "requests==2.31.0\n"},
        ),
        "secret leak attack": Action(
            kind="file",
            reads=["/app/.env"],
            workspace_files={"/app/.env": "EXAMPLE_KEY=FAKE-TEST-TOKEN-0123456789ABCDEF"},
            changes={"artifacts/debug.log": "API key loaded: FAKE-TEST-TOKEN-0123456789ABCDEF"},
        ),
    }

    for name, action in cases.items():
        verdict = guard.check(action)
        print(f"[{verdict.decision.upper():5s}] {name:24s} — {verdict.top_reason()}")


if __name__ == "__main__":
    main()
