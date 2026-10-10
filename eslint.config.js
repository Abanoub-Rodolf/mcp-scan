import globals from "globals";
import tseslint from "typescript-eslint";

export default [
  {
    languageOptions: { 
      globals: {
        ...globals.node,
        ...globals.es2021,
      } 
    }
  },
  ...tseslint.configs.recommended,
  {
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": ["error", {
        "varsIgnorePattern": "^_",
        "argsIgnorePattern": "^_",
        "caughtErrorsIgnorePattern": "^_",
      }],
    }
  },
  {
    // A fixed sleep as synchronization is what made proxy tests flake under
    // load (2026-10-10). Wait on the real signal instead: vi.waitFor, a marker
    // file, a log or stderr line, a reply, or fake timers.
    files: ["tests/**/*.ts"],
    rules: {
      "no-restricted-syntax": ["error",
        {
          selector: "NewExpression[callee.name='Promise'][arguments.0.params.length=1] CallExpression[callee.name='setTimeout']",
          message: "No sleep promises in tests. Wait on a signal (vi.waitFor, marker file, log line, reply) or use fake timers.",
        },
        {
          selector: "ImportDeclaration[source.value=/^(node:)?timers\\/promises$/]",
          message: "No timers/promises sleeps in tests. Wait on a signal (vi.waitFor, marker file, log line, reply) or use fake timers.",
        },
        {
          selector: "CallExpression:matches([callee.name='promisify'], [callee.property.name='promisify']) > Identifier[name='setTimeout']",
          message: "No promisified setTimeout in tests. Wait on a signal (vi.waitFor, marker file, log line, reply) or use fake timers.",
        },
      ],
    },
  },
  {
    // TODO: proxy-lifecycle.test.ts still sleeps (a 300ms wait and
    // a 10ms poll interval). Convert them to signal waits, then drop this override.
    files: ["tests/commands/proxy-lifecycle.test.ts"],
    rules: { "no-restricted-syntax": "off" },
  },
];
