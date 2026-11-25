// ------------------------------------------------------------
// Function hooks
// ------------------------------------------------------------

export type AfterCallback = (
    prop: string,
    result: any,
    args: any[]
) => void | Promise<void>;

const functionCallbacks = new Map<string, AfterCallback[]>();

// ------------------------------------------------------------
// Proxied functions
// ------------------------------------------------------------

export const proxiedGlobals = new Proxy<Record<string, any>>(
    {},
    {
        set(target, prop, value): boolean {
            const key = String(prop);

            if (typeof value !== 'function') {
                target[key] = value;
                return true;
            }

            // Do not wrap an already wrapped function
            if (value.__wrapped === true) {
                target[key] = value;
                return true;
            }

            const originalFn = value;

            const wrappedFn = function (this: unknown, ...args: any[]): any {

                let result: any;

                try {
                    result = originalFn.apply(this, args);
                } catch (error) {
                    throw error;
                }

                // ------------------------------------------------
                // Run registered AFTER callbacks
                // ------------------------------------------------

                const executeCallbacks = (resolvedResult: any) => {

                    const callbacks = functionCallbacks.get(key) ?? [];

                    for (const callback of callbacks) {
                        try {
                            const callbackResult = callback(key, resolvedResult, args);

                            if (
                                callbackResult &&
                                typeof callbackResult.then === 'function'
                            ) {
                                Promise.resolve(callbackResult).catch(
                                    (error) => {
                                        console.error(`[HOOK] Callback failed for '${key}':`, error);
                                    }
                                );
                            }
                        } catch (error) {
                            console.error(`[HOOK] Callback failed for '${key}':`,error);
                        }
                    }

                    return resolvedResult;
                };

                // ------------------------------------------------
                // Promise result
                // ------------------------------------------------

                if (
                    result !== null &&
                    typeof result === 'object' &&
                    typeof result.then === 'function'
                ) {
                    return Promise.resolve(result).then(
                        executeCallbacks
                    );
                }

                // ------------------------------------------------
                // Synchronous result
                // ------------------------------------------------

                return executeCallbacks(result);
            };

            Object.defineProperty(wrappedFn, '__wrapped', {
                value: true,
                enumerable: false,
                configurable: false,
                writable: false,
            });

            target[key] = wrappedFn;

            return true;
        },
    }
);

// ------------------------------------------------------------
// Register callback
// ------------------------------------------------------------

export const registerFunctionCallback = (
    functionName: string,
    callback: AfterCallback
): void => {
    const callbacks = functionCallbacks.get(functionName) ?? [];
    callbacks.push(callback);
    functionCallbacks.set(functionName, callbacks);

};