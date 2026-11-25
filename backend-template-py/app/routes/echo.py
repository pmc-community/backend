from app.route_types import RouteDefinition

# ------ MIDDLEWARES --------
from app.middleware.scopes import require_scope
from app.middleware.no_body_limiter import no_body_limiter
from app.middleware.query_parameter_limiter import query_parameter_limiter
# ------ END MIDDLEWARES -----


def processor(route, c):
    client = c.get("client")

    return c.json({"status": "ok", "client": client["id"]})


route = RouteDefinition(
    route_type="protected",
    method="get",
    middlewares=[
        no_body_limiter,
        query_parameter_limiter(max_parameters=0),
        require_scope("read:echo"),
        # require_scope("read:echo", "additional:scope"),  # --> multiple scopes required
    ],
    processor=processor,
)
