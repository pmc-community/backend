from app.route_types import RouteDefinition


def processor(route, c):
    param = c.req.param("p1")  # matches the bracket name exactly

    return c.json({"status": "ok", "param": param})


route = RouteDefinition(
    method="post",
    route_type="protected",
    processor=processor,
)
