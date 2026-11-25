"""
------------------------------------------------------------
Request schemas (Pydantic - the equivalent of the zod schemas)
------------------------------------------------------------
"""

from __future__ import annotations

import re
from typing import Any, Type

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

# Same expression zod 4 uses for z.email()
_EMAIL_RE = re.compile(
    r"^(?!\.)(?!.*\.\.)([A-Za-z0-9_'+\-\.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}\Z"
)


class UserSchema(BaseModel):
    # extra="forbid"  --> the request body must match exactly the schema.
    #                     Remove it if at least the required keys must be present.
    # strict=True     --> no type coercion (z.string() does not coerce either).
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1)
    email: str

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        if not _EMAIL_RE.match(value):
            raise ValueError("Invalid email address")

        return value


user_schema = UserSchema


# ------------------------------------------------------------
# safeParse equivalent
# ------------------------------------------------------------

_ZOD_CODES = {
    "missing": "invalid_type",
    "string_type": "invalid_type",
    "model_type": "invalid_type",
    "dict_type": "invalid_type",
    "string_too_short": "too_small",
    "extra_forbidden": "unrecognized_keys",
    "value_error": "invalid_format",
}


def _issue_message(error: dict) -> str:
    kind = error["type"]
    loc = error.get("loc", ())

    if kind == "missing":
        return "Invalid input: expected string, received undefined"

    if kind == "string_type":
        return "Invalid input: expected string"

    if kind in ("model_type", "dict_type"):
        return "Invalid input: expected object"

    if kind == "string_too_short":
        minimum = error.get("ctx", {}).get("min_length", 1)
        return f"Too small: expected string to have >={minimum} characters"

    if kind == "extra_forbidden":
        return f'Unrecognized key: "{loc[-1] if loc else ""}"'

    if kind == "value_error":
        return str(error.get("ctx", {}).get("error", "Invalid input")).removeprefix("Value error, ")

    return error.get("msg", "Invalid input")


def safe_parse(schema: Type[BaseModel], value: Any) -> dict:
    """
    Returns ``{"success": True, "data": <dict>}`` or
    ``{"success": False, "issues": [{"code", "path", "message"}, ...]}``.
    """
    try:
        model = schema.model_validate(value)
    except ValidationError as error:
        return {
            "success": False,
            "issues": [
                {
                    "code": _ZOD_CODES.get(item["type"], "custom"),
                    "path": list(item.get("loc", ())),
                    "message": _issue_message(item),
                }
                for item in error.errors()
            ],
        }

    return {"success": True, "data": model.model_dump()}
