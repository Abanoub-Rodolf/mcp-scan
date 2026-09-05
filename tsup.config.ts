import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: {
      index: 'src/index.ts',
    },
    format: ['esm'],
    target: 'node18',
    platform: 'node',
    clean: true,
    dts: true,
    minify: true,
    shims: true,
    banner: {
      js: '#!/usr/bin/env node',
    },
    outDir: 'dist',
    // Removed noExternal to avoid dynamic require issues with built-ins in bundled ESM.
    // blessed/blessed-contrib are optionalDependencies now, so tsup no longer
    // auto-externals them (it only does that for `dependencies` and
    // `peerDependencies`); without this, esbuild tries to bundle blessed's
    // optional terminal widget and chokes on its unmet term.js/pty.js requires.
    external: ['blessed', 'blessed-contrib'],
  },
  {
    entry: {
      lib: 'src/lib.ts',
    },
    format: ['esm', 'cjs'],
    target: 'node18',
    platform: 'node',
    dts: true,
    minify: true,
    shims: true,
    outDir: 'dist',
    // Removed noExternal
  },
  {
    entry: {
      action: 'action/src/action.ts',
    },
    format: ['cjs'],
    target: 'node24',
    platform: 'node',
    dts: false,
    minify: true,
    shims: true,
    outDir: 'action/dist',
    // The action runs standalone (no node_modules in the runner context),
    // so every runtime dependency must be inlined.
    noExternal: [/.*/],
  }
]);
