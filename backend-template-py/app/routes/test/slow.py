import asyncio

from app.route_types import RouteDefinition

# ------ MIDDLEWARES --------
from app.middleware.no_body_limiter import no_body_limiter
# ------ END MIDDLEWARES -----


async def processor(route, c):
    print("SLOW REQUEST START")

    await asyncio.sleep(10)  # simulating slow route with a 10sec delay

    print("SLOW REQUEST FINISHED")

    return c.json({"status": "simulated slow request completed"})


route = RouteDefinition(
    route_type="public",
    method="get",
    middlewares=[no_body_limiter],
    processor=processor,
)
