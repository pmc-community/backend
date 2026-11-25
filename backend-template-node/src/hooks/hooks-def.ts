import { registerFunctionCallback } from './hooks';

export const registerHooks = (): void => {

    // example hook on log event
    registerFunctionCallback(
        'logEvent',
        (name, result, args) => {
            console.log(`[HOOHK] Function '${name}' returned: requestId=${result}`);
        }
    );

};