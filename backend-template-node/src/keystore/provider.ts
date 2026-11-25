export async function keystoreProvider() {
    switch (process.env.DEPLOY_ENV) {
        case 'local':
            return import('../../src/keystore/local/keystore');
        case 'simprod':
            return import('../../src/keystore/local/keystore');

        // case 'production':
        //     return import('../../src/keystore/production/keystore');

        default:
            throw new Error(
                `Unsupported DEPLOY_ENV: ${process.env.DEPLOY_ENV}`
            );
    }
}