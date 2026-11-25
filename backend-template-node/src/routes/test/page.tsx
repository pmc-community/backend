// normally used as in dev: https://192.168.134:3000/test/page

import type { RouteDefinition } from '../../types/route';
import { jsxRenderer } from 'hono/jsx-renderer';

//------ MIDDLEWARES --------
import { noBodyLimiter } from '../../middleware/noBodyLimiter';
//------ END MIDDLEWARES -----

const route: RouteDefinition = {
    routeType: 'public',
    method: 'get',
    middlewares: [
        noBodyLimiter,
        jsxRenderer(({ children }) => {
            return (
                <html>
                    <head>
                        <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
                    </head>
                    <body style={{ padding: '20px' }}>
                        <header>Menu</header>
                        <main>{children}</main>

                        <script
                            dangerouslySetInnerHTML={{
                                __html: `
                                    $('#testBtn').click(function () {
                                        console.log('1234');
                                    });
                                `,
                            }}
                        />
                    </body>
                </html>
            );
        }),
    ],
    processor: async (route, c) => {
        return c.render(
            <>
                <h1>Hello</h1>
                <p>This is rendered with Hono JSX.</p>
                <button id="testBtn">Test</button>
            </>,
        );
    },
};

export default route;