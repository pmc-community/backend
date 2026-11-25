from app.hooks.hooks import register_function_callback


def register_hooks() -> None:
    # example hook on log event
    register_function_callback(
        "logEvent",
        lambda name, result, args: print(
            f"[HOOHK] Function '{name}' returned: requestId={result}"
        ),
    )
