# normally used as in dev: https://192.168.134:3000/test/page

from app.route_types import RouteDefinition

# ------ MIDDLEWARES --------
from app.middleware.no_body_limiter import no_body_limiter
# ------ END MIDDLEWARES -----

_LAYOUT = """
<!DOCTYPE html>
<html>
    <head>
        <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    </head>
    <body style="padding:20px">
        <header>Menu</header>
        <main>{content}</main>
        <script>
            $('#testBtn').click(function () {{
                console.log('1234');
            }});
        </script>
    </body>
</html>
"""

_CONTENT = (
    "<h1>Hello</h1>"
    "<p>This is rendered with a FastAPI/Starlette HTML response.</p>"
    '<button id="testBtn">Test</button>'
)


async def processor(route, c):
    return c.html(_LAYOUT.format(content=_CONTENT))


route = RouteDefinition(
    route_type="public",
    method="get",
    middlewares=[no_body_limiter],
    processor=processor,
)
