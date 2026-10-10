import globals from "globals";
import tseslint from "typescript-eslint";

const ban = what => `No ${what} in tests. Wait on a signal (vi.waitFor, marker file, log line, reply) or use fake timers.`;
const NO_TIMERS = ban("node:timers imports (timers.promises is a sleep)");
// every way to name the module: static, dynamic, require, getBuiltinModule
const TIMERS_MODULE = "/^(node:)?timers(\\/promises)?$/";
const TIMERS = new Set(["setTimeout", "setInterval"]);
const GLOBALS = new Set(["globalThis", "global", "window", "self"]);
const FNS = new Set(["ArrowFunctionExpression", "FunctionExpression", "FunctionDeclaration"]);
// expressions whose value is the value of one operand
const PASSES = new Set(["LogicalExpression", "TSAsExpression", "TSNonNullExpression", "TSSatisfiesExpression", "ArrayExpression"]);

const isTimer = n => n.type === "CallExpression" && (
  (n.callee.type === "Identifier" && TIMERS.has(n.callee.name)) ||
  (n.callee.type === "MemberExpression" && !n.callee.computed && n.callee.object.type === "Identifier" &&
    GLOBALS.has(n.callee.object.name) && n.callee.property.type === "Identifier" && TIMERS.has(n.callee.property.name)));

// Logging a value does not take ownership of it.
const isConsole = c => c.callee.type === "MemberExpression" && c.callee.object.name === "console";

// A sleep promise: the resolver (first executor param, any constructor name)
// reaches a timer and goes nowhere else, `setTimeout(r, 5)` or
// `setTimeout(() => r(), 5)`. It is not a sleep when the resolver is also handed
// off: passed to a call, assigned to an outer or member target, returned, or put
// in an object that is. Then the timer is a fallback in a race on a real signal.
// A timer whose callback only throws or rejects never touches the resolver, so
// a deadline guard passes on its own. Aliases (`const a = r`, `r.bind(...)`) are
// followed through the scope manager, so shadowing needs no special case.
const noSleepPromise = {
  meta: { type: "problem", schema: [] },
  create(context) {
    const message = ban("sleep promises");
    const src = context.sourceCode;
    const declared = (node, pick) => src.getDeclaredVariables(node).find(pick);

    // Where does the executor's resolver end up: on a timer, handed off, or both?
    // `obj`: the variable holds a `Promise.withResolvers()` result, so only
    // `.resolve` of it is the resolver, and the object itself going anywhere hands it off.
    const analyze = (exec, resolver, obj = false) => {
      const inside = n => n.range[0] >= exec.range[0] && n.range[1] <= exec.range[1];
      const fnsOf = site => {
        const fns = [];
        for (let n = site; n && n !== exec; n = n.parent) if (FNS.has(n.type)) fns.push(n);
        return fns;
      };
      const none = () => ({ timer: false, given: false });
      const merge = (out, x) => { out.timer ||= x.timer; out.given ||= x.given; };
      const stack = new Set();
      const memo = new Map();

      // A variable stands for the value it holds: follow every read of it.
      const follow = v => {
        const out = none();
        if (!v || stack.has(v)) return out;
        stack.add(v);
        for (const ref of v.references) {
          if (ref.isWriteOnly()) continue;
          const m = ref.identifier.parent;
          if (!obj || m.type !== "MemberExpression" || m.object !== ref.identifier) merge(out, trace(ref.identifier));
          else if ((m.computed ? m.property.value : m.property.name) === "resolve") merge(out, trace(m));
        }
        stack.delete(v);
        return out;
      };
      // A function runs on a timer or is given away; its calls count the same way.
      const fnFlow = f => {
        if (memo.has(f)) return memo.get(f) ?? none();
        memo.set(f, null);
        const r = f.type === "FunctionDeclaration" ? follow(declared(f, v => v.defs.some(d => d.type === "FunctionName"))) : trace(f);
        memo.set(f, r);
        return r;
      };

      // How is the value of expression `e` consumed?
      const trace = e => {
        const out = none();
        const hit = (kind, site) => {
          const fns = fnsOf(site);
          // inside a nested function, only a function that is itself given counts
          const owned = fns.some(f => fnFlow(f).given);
          if (kind === "timer" || fns.some(f => fnFlow(f).timer)) out.timer = true;
          if (kind === "given" ? !fns.length || owned : kind === "call" && owned) out.given = true;
        };
        let p = e.parent;
        if (p.type === "MemberExpression" && p.object === e && !p.computed && p.parent.type === "CallExpression" && p.parent.callee === p) {
          const how = p.property.name;
          // `r.call(...)` and `r.apply(...)` run the resolver, like `r()`
          if (how === "call" || how === "apply") { hit("call", p.parent); return out; }
          // `r.bind(...)` stands for the resolver
          if (how === "bind") {
            e = p.parent;
            p = e.parent;
          }
        }
        switch (p.type) {
          case "CallExpression":
          case "NewExpression":
            if (p.callee === e) hit("call", p);
            // the callback, or an argument the timer passes to it (`setTimeout(go, 5, r)`)
            else if (isTimer(p)) { if (p.arguments[0] === e || p.arguments.indexOf(e) > 1) hit("timer", p); }
            else if (!isConsole(p)) {
              // `setTimeout(once(r), 5)`: the call only wraps the resolver for the timer
              const t = trace(p);
              hit(t.timer && !t.given ? "timer" : "given", p);
            }
            break;
          case "AssignmentExpression": {
            if (p.right !== e) break;
            let v = null;
            if (p.left.type === "Identifier") {
              for (let s = src.getScope(p); s && !v; s = s.upper) v = s.set.get(p.left.name);
            }
            if (v?.defs[0] && inside(v.defs[0].name)) merge(out, follow(v));
            else hit("given", p);
            break;
          }
          case "VariableDeclarator":
            if (p.init === e && p.id.type === "Identifier") merge(out, follow(declared(p, v => v.name === p.id.name)));
            break;
          case "ReturnStatement":
            hit("given", p);
            break;
          case "ArrowFunctionExpression":
            if (p.body === e) hit("given", p);
            break;
          case "ConditionalExpression":
            if (p.test !== e) merge(out, trace(p));
            break;
          case "SequenceExpression":
            if (p.expressions.at(-1) === e) merge(out, trace(p));
            break;
          case "Property":
            if (p.value === e && p.parent.type === "ObjectExpression") merge(out, trace(p.parent));
            break;
          default:
            if (PASSES.has(p.type)) merge(out, trace(p));
        }
        return out;
      };
      return follow(resolver);
    };
    const scopeOf = n => { while (n.parent && !FNS.has(n.type)) n = n.parent; return n; };
    // the executor: inline, a function declaration, or a const holding a function
    const executor = arg => {
      if (arg?.type !== "Identifier") return arg;
      let v = null;
      for (let s = src.getScope(arg); s && !v; s = s.upper) v = s.set.get(arg.name);
      const def = v?.defs.length === 1 ? v.defs[0] : null;
      if (def?.type === "FunctionName") return def.node;
      return def?.type === "Variable" && def.node.id.type === "Identifier" ? def.node.init : null;
    };
    return {
      NewExpression(node) {
        const exec = executor(node.arguments[0]);
        if (!exec || !FNS.has(exec.type) || exec.params[0]?.type !== "Identifier") return;
        const resolver = src.getDeclaredVariables(exec).find(v => v.defs.some(d => d.type === "Parameter" && d.name === exec.params[0]));
        const { timer, given } = analyze(exec, resolver);
        if (timer && !given) context.report({ node, message });
      },
      // `const { resolve } = Promise.withResolvers()` and `const w = Promise.withResolvers()`
      CallExpression(node) {
        const c = node.callee;
        const d = node.parent;
        if (c.type !== "MemberExpression" || c.computed || c.property.name !== "withResolvers" || d.type !== "VariableDeclarator" || d.init !== node) return;
        let v = null;
        let obj = false;
        if (d.id.type === "Identifier") {
          v = declared(d, x => x.name === d.id.name);
          obj = true;
        } else if (d.id.type === "ObjectPattern") {
          const prop = d.id.properties.find(x => x.type === "Property" && !x.computed && x.key.name === "resolve");
          const id = prop?.value.type === "AssignmentPattern" ? prop.value.left : prop?.value;
          if (id?.type === "Identifier") v = declared(d, x => x.name === id.name);
        }
        if (!v) return;
        const { timer, given } = analyze(scopeOf(d), v, obj);
        if (timer && !given) context.report({ node, message });
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
        paths: ["timers", "node:timers", "timers/promises", "node:timers/promises"].map(name => ({ name, message: NO_TIMERS })),
      }],
      "no-restricted-syntax": ["error",
        {
          selector: `ImportExpression[source.value=${TIMERS_MODULE}]`,
          message: NO_TIMERS,
        },
        {
          selector: `CallExpression:matches([callee.name='require'], [callee.property.name='getBuiltinModule'])[arguments.0.value=${TIMERS_MODULE}]`,
          message: NO_TIMERS,
        },
        {
          selector: "CallExpression:matches([callee.name='promisify'], [callee.property.name='promisify']) > Identifier[name='setTimeout']",
          message: ban("promisified setTimeout"),
        },
      ],
    },
  },
];
