import globals from "globals";
import tseslint from "typescript-eslint";

const NO_TIMERS_PROMISES = "No timers/promises sleeps in tests. Wait on a signal (vi.waitFor, marker file, log line, reply) or use fake timers.";
const TIMERS = new Set(["setTimeout", "setInterval"]);
const GLOBALS = new Set(["globalThis", "global", "window", "self"]);
const FNS = new Set(["ArrowFunctionExpression", "FunctionExpression"]);

const isTimer = n => n.type === "CallExpression" && (
  (n.callee.type === "Identifier" && TIMERS.has(n.callee.name)) ||
  (n.callee.type === "MemberExpression" && !n.callee.computed && n.callee.object.type === "Identifier" &&
    GLOBALS.has(n.callee.object.name) && n.callee.property.type === "Identifier" && TIMERS.has(n.callee.property.name)));

// A sleep promise: a timer inside a promise executor that fires the executor's
// resolver (first param, any param count, any constructor name), either handed
// over directly, `setTimeout(r, 5)`, or wrapped, `setTimeout(() => r(), 5)`.
// A timer whose callback throws or rejects is a deadline guard and passes.
const noSleepPromise = {
  meta: { type: "problem", schema: [] },
  create(context) {
    const message = "No sleep promises in tests. Wait on a signal (vi.waitFor, marker file, log line, reply) or use fake timers.";
    const executors = anc => anc.filter(a => FNS.has(a.type) && a.parent?.type === "NewExpression" &&
      a.parent.arguments[0] === a && a.params[0]?.type === "Identifier");
    return {
      CallExpression(node) {
        const anc = context.sourceCode.getAncestors(node).reverse();
        if (isTimer(node)) {
          const cb = node.arguments[0];
          const name = cb?.type === "Identifier" ? cb.name
            : cb?.type === "CallExpression" && cb.callee.type === "MemberExpression" && cb.callee.property.name === "bind" && cb.callee.object.type === "Identifier" ? cb.callee.object.name
            : null;
          if (name && executors(anc).some(e => e.params[0].name === name)) context.report({ node, message });
          return;
        }
        if (node.callee.type !== "Identifier") return;
        // a call of the resolver inside a callback that a timer receives
        anc.forEach((fn, i) => {
          const timerCb = FNS.has(fn.type) && fn.parent?.type === "CallExpression" && fn.parent.arguments[0] === fn && isTimer(fn.parent);
          if (timerCb && executors(anc.slice(i)).some(e => e.params[0].name === node.callee.name)) {
            context.report({ node: fn.parent, message });
          }
        });
      },
    };
  },
};

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
    // Known gap: aliasing the timer first (`const t = setTimeout; t(r, 5)`) is not
    // followed. Reviewers catch that one.
    files: ["tests/**/*.ts"],
    plugins: { local: { rules: { "no-sleep-promise": noSleepPromise } } },
    rules: {
      "local/no-sleep-promise": "error",
      "no-restricted-imports": ["error", {
        paths: ["timers/promises", "node:timers/promises"].map(name => ({ name, message: NO_TIMERS_PROMISES })),
      }],
      "no-restricted-syntax": ["error",
        {
          selector: "ImportExpression[source.value=/^(node:)?timers\\/promises$/]",
          message: NO_TIMERS_PROMISES,
        },
        {
          selector: "CallExpression[callee.name='require'][arguments.0.value=/^(node:)?timers\\/promises$/]",
          message: NO_TIMERS_PROMISES,
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
    rules: { "no-restricted-syntax": "off", "local/no-sleep-promise": "off" },
  },
];
