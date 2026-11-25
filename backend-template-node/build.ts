import * as esbuild from 'esbuild';

await esbuild.build({
    entryPoints: ['server.ts'],
    bundle: true,
    platform: 'node',
    target: 'node22',
    format: 'esm',
    outdir: 'dist',

    // Enable separate files for dynamic imports
    splitting: true,

    sourcemap: false,

    // Keep Node dependencies external
    packages: 'external',
});