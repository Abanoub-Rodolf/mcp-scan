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
// A timer whose callback throws or rejects is a deadline guard and passes. So
// does a resolve-style guard when the executor also hands the resolver to
// something else (an argument, an assignment, a listener): the timer is then a
// fallback in a race on a real signal, not the whole wait.
const noSleepPromise = {
  meta: { type: "problem", schema: [] },
  create(context) {
    const message = "No sleep promises in tests. Wait on a signal (vi.waitFor, marker file, log line, reply) or use fake timers.";
    const executors = anc => anc.filter(a => FNS.has(a.type) && a.parent?.type === "NewExpression" &&
      a.parent.arguments[0] === a && a.params[0]?.type === "Identifier");
    // Does the executor use its resolver anywhere except as a timer's callback?
    const handsOff = (exec, name) => {
      const keys = context.sourceCode.visitorKeys;
      let found = false;
      const walk = (n, inTimerCb) => {
        if (found || !n || typeof n.type !== "string") return;
        const p = n.parent;
        if (n.type === "Identifier" && n.name === name && n !== exec.params[0] &&
            !(p.type === "MemberExpression" && p.property === n && !p.computed) &&
            !(p.type === "Property" && p.key === n && !p.computed && !p.shorthand)) {
          const direct = isTimer(p) && p.arguments[0] === n;
          // `r.length` is no handoff; a bare `r()` in the executor body itself only resolves at once
          const called = p.type === "CallExpression" && p.callee === n;
          if (!direct && !inTimerCb && p.type !== "MemberExpression" && !(called && nearestFn(n) === exec)) found = true;
          return;
        }
        const timerCb = FNS.has(n.type) && n.parent?.type === "CallExpression" && n.parent.arguments[0] === n && isTimer(n.parent);
        for (const k of keys[n.type] ?? []) {
          for (const c of [].concat(n[k] ?? [])) walk(c, inTimerCb || timerCb);
        }
      };
      walk(exec.body, false);
      return found;
    };
    const nearestFn = n => { let a = n.parent; while (a && !FNS.has(a.type)) a = a.parent; return a; };
    const flag = (exec, name, node) => { if (!handsOff(exec, name)) context.report({ node, message }); };
    return {
      CallExpression(node) {
        const anc = context.sourceCode.getAncestors(node).reverse();
        if (isTimer(node)) {
          const cb = node.arguments[0];
          const name = cb?.type === "Identifier" ? cb.name
            : cb?.type === "CallExpression" && cb.callee.type === "MemberExpression" && cb.callee.property.name === "bind" && cb.callee.object.type === "Identifier" ? cb.callee.object.name
            : null;
          if (name) executors(anc).filter(e => e.params[0].name === name).forEach(e => flag(e, name, node));
          return;
        }
        if (node.callee.type !== "Identifier") return;
        // a call of the resolver inside a callback that a timer receives
        anc.forEach((fn, i) => {
          const timerCb = FNS.has(fn.type) && fn.parent?.type === "CallExpression" && fn.parent.arguments[0] === fn && isTimer(fn.parent);
          if (timerCb) executors(anc.slice(i)).filter(e => e.params[0].name === node.callee.name).forEach(e => flag(e, node.callee.name, fn.parent));
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
];
