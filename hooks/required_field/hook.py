"""Example hook: require a nonblank purpose before an action."""

import json
import sys


def main() -> None:
    try:
        context = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError):
        print(json.dumps({"decision": "block", "reason": "Input must be valid JSON."}))
        return
    purpose = context.get("purpose") if isinstance(context, dict) else None
    if not isinstance(purpose, str) or not purpose.strip():
        print(json.dumps({
            "decision": "block",
            "reason": "Provide a nonblank purpose before running the action.",
        }))


if __name__ == "__main__":
    main()
