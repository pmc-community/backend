from app.route_types import RouteDefinition


def processor(route, c):
    pa = c.req.param("pa")
    pb = c.req.param("pb")

    return c.json({"status": "ok", "pa": pa, "pb": pb})


route = RouteDefinition(
    method="post",
    route_type="public",
    processor=processor,
)
