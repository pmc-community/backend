from app.route_types import RouteDefinition

# ------ MIDDLEWARES --------
from app.middleware.no_body_limiter import no_body_limiter
from app.middleware.query_parameter_limiter import query_parameter_limiter
# ------ END MIDDLEWARES -----


def processor(route, c):
    return c.json({"status": "ok"})


route = RouteDefinition(
    route_type="public",
    method="get",
    middlewares=[
        no_body_limiter,
        query_parameter_limiter(max_parameters=0),
    ],
    processor=processor,
)
