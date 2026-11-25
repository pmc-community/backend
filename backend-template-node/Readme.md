# Backend template
This repo contains the code for a hono based API server with the most usual addtional protection and control middlewares. The code is fully functional for testing on local environments and for deployments in environments supporting node:fs. For other deployments (such as Cloudflare workers) it is necessary to add specfific code to manage AAPI keyes or other data necessary for the middlewares, as instructed in code comments.

# 1. install packages

    clone the repo backend-template and run `npm install`

# 2. rename the server

    edit .env and package.json

# 3. get the IP

    macOS: ipconfig getifaddr en0
    Linux: hostname -I
    Windows: ipconfig

# 4. generate a ssl cert for the localhost

    macOS:
        brew install mkcert
        mkcert -install

    Windows:
        winget install FiloSottile.mkcert
        mkcert -install
    
    Linux (Ubuntu/Debian):
        sudo apt install mkcert
        mkcert -install
    
    IMPORTANT: The following 2 lines must be executed each time when the localhost IP changes

        cd <project-root-directory>
        mkcert localhost 127.0.0.1 <localhost_IP>

# 5. rename the cert generated files (if needed):
        mv <generated-file>.pem cert.pem
        mv <generated-file-key>.pem key.pem


# 6. create tsconfig.json

    npx tsc --init

# 7. include the next into tsconfig.json

    {
    "compilerOptions": {
        "target": "ES2022",
        "module": "ESNext",
        "moduleResolution": "bundler",
        "types": ["node"],
        "esModuleInterop": true,
        "skipLibCheck": true,
        "strict": true,
        "outDir": "dist"
    },
        "include": ["*.ts", "src/**/*.ts", "scripts/**/*.ts"]
    }

# 8. check package.json, must contain:

    "name": "<whatever-name-you-want-for-your-server>",
    "version": "1.0.0",
    "type": "module", // --> important
    "private": true,

# 9. start server 

    npm run dev (local)
    npm run start (prod or simprod)

# 10. to generate a new api key:

    npx tsx scripts/generate-key.ts

    raw key to be used in api request in header: Authorization: Bearer <raw_api_key>
    has key to added to keystore.json together with the scopes granted to that api key

