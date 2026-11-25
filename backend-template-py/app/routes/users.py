from app.config.body_schemas import user_schema
from app.route_types import RouteDefinition

# ------ MIDDLEWARES --------
from app.middleware.ip_restriction import ip_restriction
from app.middleware.json_only_limiter import json_only_limiter
from app.middleware.per_key_limiter import per_key_rate_limiter
from app.middleware.scopes import require_scope
from app.middleware.signed_request_protection import signed_request_protection
from app.middleware.size_limiter import size_limiter
from app.middleware.timeout_limiter import timeout_limiter
from app.middleware.validator import z_validator
# ------ END MIDDLEWARES -----

from app.helpers.err_handler import ip_restriction_error, z_validator_error
from app.helpers.js import env_int
from app.helpers.utilities import get_client_ip


async def get_signing_secret(c, client_id):
    # testing signed request feature
    # is hardcoded for testClient, having a hardcoded client secret
    # here it must be a function getting the secret from the secrets storage
    # same clientId and secret are configured in POSTMAN pre-request scripts
    # see scripts/postman-pre-request.js
    print("Signing secret requested for client:", client_id)

    if client_id == "testClient":
        return "test-secret-123"

    return None


async def processor(route, c):
    body = c.req.valid("json")

    return c.json({"received": body}, 201)


route = RouteDefinition(
    route_type="protected",
    method="post",
    middlewares=[
        ip_restriction(
            get_client_ip,
            deny_list=[],
            allow_list=["192.168.1.0/24"],
            # allow_list=["192.168.1.111"],
            on_error=lambda remote, c: ip_restriction_error(remote, c),
        ),
        signed_request_protection(get_signing_secret=get_signing_secret),
        per_key_rate_limiter(10),
        require_scope("write:users"),
        size_limiter(env_int("maxBytesBase", "1024") ** 2),
        json_only_limiter,
        z_validator("json", user_schema, lambda result, c: z_validator_error(result, c)),
        timeout_limiter(1),
    ],
    processor=processor,
    openapi_request_body={
        "required": True,
        "content": {"application/json": {"schema": user_schema.model_json_schema()}},
    },
)
