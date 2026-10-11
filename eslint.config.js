import globals from "globals";
import tseslint from "typescript-eslint";

const ban = what => `No ${what} in tests. Wait on a signal (vi.waitFor, marker file, log line, reply) or use fake timers.`;
// Whole module, not just promises: nothing here needs it, and the globals
// setTimeout, setInterval and setImmediate are the same functions without an import.
const NO_TIMERS = ban("imports of the timers module (timers.promises is a sleep, and the global setTimeout, setInterval and setImmediate need no import)");
// one list feeds the static-import paths and the selector regex for the dynamic forms
const TIMERS_MODULES = ["timers", "timers/promises"].flatMap(m => [m, `node:${m}`]);
const TIMERS_MODULE = `/^(${TIMERS_MODULES.map(m => m.replace("/", "\\/")).join("|")})$/`;
// a module name is a string or a template without holes: 'timers' or `timers`.
// A template with holes (`timers${x}`) names nothing we can read, so it is not banned.
const isTimersModule = path => `:matches([${path}.value=${TIMERS_MODULE}], [${path}.quasis.length=1][${path}.quasis.0.value.cooked=${TIMERS_MODULE}])`;
// the ways to load a module by name: require, module.require, process.getBuiltinModule,
// and the function createRequire(...) returns, called in place
const REQUIRES = ["[callee.name='require']", "[callee.property.name='require']", "[callee.property.value='require']",
  "[callee.property.name='getBuiltinModule']", "[callee.property.value='getBuiltinModule']",
  "[callee.callee.name='createRequire']", "[callee.callee.property.name='createRequire']"];
const TIMERS = new Set(["setTimeout", "setInterval"]);
const GLOBALS = new Set(["globalThis", "global", "window", "self"]);
const FNS = new Set(["ArrowFunctionExpression", "FunctionExpression", "FunctionDeclaration"]);
// expressions whose value is the value of one operand
const PASSES = new Set(["LogicalExpression", "TSAsExpression", "TSNonNullExpression", "TSSatisfiesExpression", "ArrayExpression", "SpreadElement"]);
// a type assertion, `!`, `?.` or a comma expression still evaluates to its operand
const WRAPS = new Set(["TSAsExpression", "TSNonNullExpression", "TSSatisfiesExpression", "TSTypeAssertion", "ChainExpression"]);
const inner = e => {
  for (;;) {
    if (WRAPS.has(e.type)) e = e.expression;
    else if (e.type === "SequenceExpression") e = e.expressions.at(-1);
    else return e;
  }
};
// the outermost wrapper around a read: `w as any`, `w!`, `(0, w)`
const outer = n => {
  for (let p = n.parent; p && (WRAPS.has(p.type) || (p.type === "SequenceExpression" && p.expressions.at(-1) === n)); p = n.parent) n = p;
  return n;
};
// the name of a plain or literal key: w.resolve, w["resolve"], w[`resolve`], { resolve: r }, a[0]
const nameOf = (computed, k) => {
  if (!computed) return k.type === "Identifier" ? k.name : k.value;
  if (k.type === "Literal") return k.value;
  if (k.type === "TemplateLiteral" && !k.expressions.length) return k.quasis[0].value.cooked;
  return undefined;
};
const lookupIn = (src, node) => {
  for (let s = src.getScope(node); s; s = s.upper) if (s.set.has(node.name)) return s.set.get(node.name);
  return null;
};
// nameOf, and a computed key that is a const string reads as that string: `const k = "setTimeout"; o[k]`
const keyIn = (src, computed, k) => {
  const name = nameOf(computed, k);
  if (name !== undefined || !computed || k.type !== "Identifier") return name;
  const def = lookupIn(src, k)?.defs;
  const d = def?.length === 1 && def[0].type === "Variable" && def[0].parent.kind === "const" ? def[0].node : null;
  return d?.id.type === "Identifier" && d.init ? nameOf(true, inner(d.init)) : undefined;
};
function* nodes(n) {
  yield n;
  for (const [k, v] of Object.entries(n)) {
    if (k === "parent") continue;
    for (const c of Array.isArray(v) ? v : [v]) if (c && typeof c.type === "string") yield* nodes(c);
  }
}
// calls that keep their argument in a container someone else can reach later
const STORES = new Set(["push", "unshift", "set", "add"]);
// members of a function that are not the function, and calls that take an element out of a container
const INERT = new Set(["length", "name", "toString", "call", "apply", "bind"]);
const TAKES = new Set(["shift", "pop", "at"]);
// calls on a stored-resolver container that do not run what is in it
const BENIGN = new Set(["clear", "delete", "has"]);

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
// A resolver handed to a helper declared in this file counts as what the helper
// does with it. A resolver stored in a container (`rs[0] = r`, `rs.push(r)`,
// `pending.set(k, r)`) is a sleep when a timer in the file calls something out of
// that same container.
// Known gaps (an AST rule, not a dataflow engine). A sleep still gets through when:
// - the resolver reaches a timer through a helper that is not a function declared in this file
//   (imported, a method like `h.after(r)`, `this.after(r)`), or the timer is built in another module;
// - the timer is `let` or reassigned (`let t = setTimeout; t(r, 5)`), or reached through a computed key
//   the file does not spell out (`globalThis[k](r, 5)` with k from a call);
// - a timer or a script is passed on as a value (`run(setTimeout as never)`), or its name is built at
//   runtime (`'set' + 'Timeout'`, a script string joined from parts);
// - the resolver is run as `r['call']()` or handed over as `setTimeout(r.call, 5)`;
// - a stored resolver (`rs.push(r)`, `rs[0] = r`) is run by a timer without a call rooted at the same
//   container (`const [f] = rs; f()`), or sits behind `this.` or an undeclared name;
// - `Promise.withResolvers()` is kept on a property (`this.d = Promise.withResolvers()`);
// - the timers module is loaded through a stored `createRequire(...)` result (`const req = createRequire(u); req('timers')`);
// - a clock busy-wait calls something (`while (Date.now() < end) { check(); }` is a poll) or reads another
//   clock (`process.hrtime`);
// - the race fallback, which is the one exemption kept: a resolver that is also handed to any call, store,
//   return or object (`new Promise((r) => { noop(r); setTimeout(r, 50); })`) is a timeout fallback in a race on a
//   real signal, so it passes. Rewrite such a test as a deadline guard that rejects to get strictness.
// Accepted false positives: a timer callback that calls anything rooted at a container the resolver was
// stored in (other than `clear`, `delete`, `has`) counts as running it; any `.waitForTimeout` on any object
// is reported, and a script string that merely names setTimeout is reported.
const noSleepPromise = {
  meta: { type: "problem", schema: [] },
  create(context) {
    const message = ban("sleep promises");
    const src = context.sourceCode;
    const declared = (node, pick) => src.getDeclaredVariables(node).find(pick);
    const lookup = node => lookupIn(src, node);
    const keyOf = (computed, k) => keyIn(src, computed, k);
    // the variable at the root of `a`, `a.b[0]`, `a.get(1)()`
    const rootOf = n => {
      for (n = inner(n); n.type === "MemberExpression" || n.type === "CallExpression"; n = inner(n.type === "CallExpression" ? n.callee : n.object));
      return n.type === "Identifier" ? lookup(n) : null;
    };
    // Where is `pat` bound to `name`: the keys leading to it, and a default value
    // that applies to it directly. `{ a: [, b = 1] }` finds b at ["a", 1] with 1.
    const locate = (pat, name, path = [], dflt = null) => {
      if (pat.type === "Identifier") return pat === name ? { path, dflt } : null;
      if (pat.type === "AssignmentPattern") return locate(pat.left, name, path, pat.right);
      if (pat.type === "ObjectPattern") {
        for (const p of pat.properties) {
          const k = p.type === "Property" ? keyOf(p.computed, p.key) : undefined;
          const r = k === undefined ? null : locate(p.value, name, [...path, k]);
          if (r) return r;
        }
      } else if (pat.type === "ArrayPattern") {
        for (const [i, el] of pat.elements.entries()) {
          const r = el && el.type !== "RestElement" ? locate(el, name, [...path, i]) : null;
          if (r) return r;
        }
      }
      return null;
    };
    // Does the value of `e`, read down `path`, hold a timer? `setTimeout`,
    // `globalThis.setTimeout`, `self["setInterval"]`, `{ wait: setTimeout }.wait`,
    // `[setTimeout][0]`, `a ?? setTimeout`, `setTimeout.bind(null)`, or a name that
    // is only ever one of those: a const, a destructured const, a parameter default.
    // `seen` is the walk that led here, one branch at a time: `o.a ?? o.b` reads `o` twice,
    // under two keys, and a node that merely finished earlier is no cycle. A false that no
    // cycle cut short stays true for the file, so a chain of `a1 = a0 ?? a0` is walked once.
    let cuts = 0;
    const known = new Map();
    const timerAt = (e, path, seen) => {
      e = inner(e);
      const key = `${e.type}${e.range}|${path}`;
      if (known.has(key)) return known.get(key);
      if (seen.has(key)) { cuts++; return false; }
      seen.add(key);
      const before = cuts;
      const r = walk(e, path, seen);
      seen.delete(key);
      if (r || cuts === before) known.set(key, r);
      return r;
    };
    const walk = (e, path, seen) => {
      switch (e.type) {
        case "Identifier": {
          if (!path.length && TIMERS.has(e.name)) return true;
          if (path.length === 1 && GLOBALS.has(e.name)) return TIMERS.has(path[0]);
          const def = lookup(e)?.defs;
          if (def?.length !== 1) return false;
          let pat, init;
          if (def[0].type === "Variable" && def[0].parent.kind === "const") ({ id: pat, init } = def[0].node);
          else if (def[0].type === "Parameter") pat = def[0].node.params?.find(x => x.range[0] <= def[0].name.range[0] && def[0].name.range[1] <= x.range[1]);
          const at = pat && locate(pat, def[0].name);
          if (!at) return false;
          return !!(init && timerAt(init, [...at.path, ...path], seen)) || !!(at.dflt && timerAt(at.dflt, path, seen));
        }
        case "MemberExpression": {
          const k = keyOf(e.computed, e.property);
          return k !== undefined && timerAt(e.object, [k, ...path], seen);
        }
        case "ObjectExpression":
          if (!path.length) return false;
          // the last property that names the key wins; a spread could hide any key
          for (const p of [...e.properties].reverse()) {
            if (p.type !== "Property") return false;
            if (String(nameOf(p.computed, p.key)) === String(path[0])) return timerAt(p.value, path.slice(1), seen);
          }
          return false;
        case "ArrayExpression": {
          const i = path[0];
          if (typeof i !== "number" || i >= e.elements.length || e.elements.slice(0, i + 1).some(x => !x || x.type === "SpreadElement")) return false;
          return timerAt(e.elements[i], path.slice(1), seen);
        }
        case "LogicalExpression":
          return timerAt(e.left, path, seen) || timerAt(e.right, path, seen);
        case "ConditionalExpression":
          return timerAt(e.consequent, path, seen) || timerAt(e.alternate, path, seen);
        case "CallExpression":
          return !path.length && methodOn(e.callee, "bind", seen);
      }
      return false;
    };
    const isTimerFn = c => timerAt(c, [], new Set());
    // `t.call`, `t.apply`, `t.bind` where t is a timer. `seen` carries the walk that
    // got here, so `const t = t.bind(null)` ends instead of starting over.
    const methodOn = (callee, how, seen = new Set()) => {
      const c = inner(callee);
      return c.type === "MemberExpression" && nameOf(c.computed, c.property) === how && timerAt(c.object, [], seen);
    };
    // What a timer call hands the timer, as `(callback, ms, ...args)`, or null when the
    // call is no timer: `t(cb, 5)`, `t.call(this, cb, 5)`, `t.apply(this, [cb, 5])`,
    // `t.bind(this)(cb, 5)`, `(0, t)(cb, 5)`.
    const timerArgs = call => {
      const c = inner(call.callee);
      if (c.type === "CallExpression" && methodOn(c.callee, "bind")) return [...c.arguments.slice(1), ...call.arguments];
      if (methodOn(c, "call")) return call.arguments.slice(1);
      if (methodOn(c, "apply")) {
        const list = call.arguments[1] && inner(call.arguments[1]);
        return list?.type === "ArrayExpression" ? list.elements.filter(Boolean) : [];
      }
      return isTimerFn(c) ? call.arguments : null;
    };

    // Where does the executor's resolver end up: on a timer, handed off, or both?
    // `obj`: the variable holds a `Promise.withResolvers()` result, so only
    // `.resolve` of it is the resolver. `.reject` and `.promise` are ignored; any
    // other read (the object itself, a rest element, an unreadable key) hands it off.
    // `const { resolve } = w` and `w?.resolve` are reads of resolve like `w.resolve`.
    // `leaks`: containers the resolver was stored in, for a timer elsewhere to run, each with
    // the member names that do not run it: `{ res, rej }` stored whole is run by `.res()`
    // and not by `.rej()`, and a `withResolvers()` object is run by `.resolve()` only.
    const busy = new Set();
    const analyze = (exec, resolver, obj = false) => {
      const inside = n => n.range[0] >= exec.range[0] && n.range[1] <= exec.range[1];
      const fnsOf = site => {
        const fns = [];
        for (let n = site; n && n !== exec; n = n.parent) if (FNS.has(n.type)) fns.push(n);
        return fns;
      };
      const none = () => ({ timer: false, given: false, leaks: [] });
      const merge = (out, x) => {
        out.timer ||= x.timer;
        out.given ||= x.given;
        out.leaks.push(...x.leaks);
      };
      // the same stores, now known to hold a value whose members `names` are not the resolver
      const except = (x, names) => ({ ...x, leaks: x.leaks.map(l => ({ root: l.root, skip: new Set([...l.skip, ...names]) })) });
      const stack = new Set();
      const memo = new Map();

      // variables that hold the withResolvers object itself, not one of its functions
      const objs = new Set(obj ? [resolver] : []);
      const sameObj = (e, v) => { const u = inner(e); if (u.type === "Identifier" && objs.has(lookup(u))) objs.add(v); return v; };
      // `w || o`, `c ? w : o`, `{ w }`, `[w]`, `{ ...w }` hold w without being w: treat as a handoff
      const holds = (n, p) => p.type === "LogicalExpression" || p.type === "ArrayExpression" || p.type === "SpreadElement"
        || (p.type === "ConditionalExpression" && p.test !== n) || (p.type === "Property" && p.parent.type === "ObjectExpression");
      // `const { resolve: r, promise } = w`: r is the resolver, promise and reject are not
      // it, and a rest element or a key we cannot read could be anything.
      const unpack = (decl, out) => {
        for (const prop of decl.id.properties) {
          const k = prop.type === "Property" ? nameOf(prop.computed, prop.key) : undefined;
          if (k === "reject" || k === "promise") continue;
          const target = prop.type === "Property" && prop.value.type === "AssignmentPattern" ? prop.value.left : prop.value;
          if (k === "resolve" && target.type === "Identifier") merge(out, follow(declared(decl, x => x.name === target.name)));
          else out.given = true;
        }
      };
      // A variable stands for the value it holds: follow every read of it.
      const follow = v => {
        const out = none();
        if (!v || stack.has(v)) return out;
        stack.add(v);
        for (const ref of v.references) {
          if (ref.isWriteOnly()) continue;
          const id = ref.identifier;
          if (!objs.has(v)) { merge(out, trace(id)); continue; }
          const n = outer(id);
          const m = n.parent;
          if (m.type === "VariableDeclarator" && m.init === n && m.id.type === "ObjectPattern") unpack(m, out);
          else if (holds(n, m)) out.given = true;
          else if (m.type !== "MemberExpression" || m.object !== n) {
            merge(out, except(trace(id), ["reject", "promise"]));
            // `const [x] = w` and the like take the object out of sight
            if (m.type === "VariableDeclarator" && m.init === n && m.id.type !== "Identifier") out.given = true;
          } else {
            const k = nameOf(m.computed, m.property);
            if (k === "reject" || k === "promise") continue;
            // `w?.resolve` is a read of resolve; a key we cannot read is a handoff
            if (k === "resolve") merge(out, trace(m.parent.type === "ChainExpression" ? m.parent : m));
            else out.given = true;
          }
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
      // What a helper declared in this file does with the argument it gets, or null
      // when it is not one (imported, a method, already being analyzed).
      const helperFlow = (call, arg) => {
        const fn = executor(call.callee);
        const i = call.arguments.indexOf(arg);
        const first = fn && FNS.has(fn.type) ? fn.params[i] : null;
        const param = first?.type === "AssignmentPattern" ? first.left : first;
        if (param?.type !== "Identifier" || busy.has(fn)) return null;
        busy.add(fn);
        const r = analyze(fn, declared(fn, v => v.defs.some(d => d.type === "Parameter" && d.name === param)));
        busy.delete(fn);
        return r;
      };

      // How is the value of expression `e` consumed?
      const trace = e => {
        const out = none();
        // `root`: the container the value is stored in, for a timer elsewhere to run
        const hit = (kind, site, root) => {
          const fns = fnsOf(site);
          // inside a nested function, only a function that is itself given counts
          const owned = fns.some(f => fnFlow(f).given);
          if (kind === "timer" || fns.some(f => fnFlow(f).timer)) out.timer = true;
          if (kind === "given" ? !fns.length || owned : kind === "call" && owned) {
            out.given = true;
            if (root) out.leaks.push({ root, skip: new Set() });
          }
        };
        let p = e.parent;
        if (p.type === "MemberExpression" && p.object === e && !p.computed && p.parent.type === "CallExpression" && p.parent.callee === p) {
          const how = p.property.name;
          // `r.call(...)` and `r.apply(...)` run the resolver, like `r()`
          if (how === "call" || how === "apply") hit("call", p.parent);
          // `r.bind(...)` stands for the resolver
          else if (how === "bind") {
            e = p.parent;
            p = e.parent;
          }
        }
        switch (p.type) {
          case "CallExpression":
          case "NewExpression": {
            const call = p.type === "CallExpression";
            const args = call ? timerArgs(p) : null;
            if (p.callee === e) hit("call", p);
            // `t.apply(null, list)` takes the whole list
            else if (call && p.arguments[1] === e && methodOn(p.callee, "apply")) hit("timer", p);
            // the callback, or an argument the timer passes to it (`setTimeout(go, 5, r)`)
            else if (args) { if (args[0] === e || args.indexOf(e) > 1) hit("timer", p); }
            // `t.bind(null, r, 5)` keeps the arguments for later
            else if (call && methodOn(p.callee, "bind")) { const i = p.arguments.indexOf(e); if (i === 1 || i > 2) hit("timer", p); }
            else if (!isConsole(p)) {
              const f = call ? helperFlow(p, e) : null;
              const m = call && inner(p.callee);
              const root = m.type === "MemberExpression" && STORES.has(nameOf(m.computed, m.property)) ? rootOf(m.object) : null;
              if (f?.timer) {
                hit("timer", p);
                if (f.given) hit("given", p);
              } else {
                // `setTimeout(once(r), 5)`: the call only wraps the resolver for the timer
                const t = trace(p);
                hit(t.timer && !t.given ? "timer" : "given", p, root);
              }
            }
            break;
          }
          case "AssignmentExpression": {
            if (p.right !== e) break;
            const v = p.left.type === "Identifier" ? lookup(p.left) : null;
            if (v?.defs[0] && inside(v.defs[0].name)) merge(out, follow(sameObj(e, v)));
            else hit("given", p, rootOf(p.left));
            break;
          }
          case "VariableDeclarator":
            if (p.init === e && p.id.type === "Identifier") merge(out, follow(sameObj(e, declared(p, v => v.name === p.id.name))));
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
            // `{ res, rej }` stored whole: calling `.rej` on it is not running the resolver
            if (p.value === e && p.parent.type === "ObjectExpression") {
              merge(out, except(trace(p.parent), p.parent.properties.filter(x => x !== p && x.type === "Property").map(x => nameOf(x.computed, x.key)).filter(k => k !== undefined && k !== nameOf(p.computed, p.key))));
            }
            break;
          case "MemberExpression": {
            // the resolver in a container: `q[0]`, `rec.resolve`, `q.shift()`
            const name = nameOf(p.computed, p.property);
            if (p.object !== e || INERT.has(name)) break;
            if (p.parent.type !== "CallExpression" || p.parent.callee !== p) merge(out, trace(p));
            else if (TAKES.has(name)) merge(out, trace(p.parent));
            break;
          }
          case "ArrayExpression": {
            // `setTimeout.apply(null, [r, 5])`: the first element is the callback
            const call = p.parent;
            if (call.type === "CallExpression" && call.arguments[1] === p && methodOn(call.callee, "apply")) {
              const i = p.elements.indexOf(e);
              if (i === 0 || i > 1) hit("timer", call);
            } else merge(out, trace(p));
            break;
          }
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
      const v = lookup(arg);
      const def = v?.defs.length === 1 ? v.defs[0] : null;
      if (def?.type === "FunctionName") return def.node;
      return def?.type === "Variable" && def.node.id.type === "Identifier" ? def.node.init : null;
    };

    // timers in the file, and promises whose resolver sits in a container (judged at the end)
    const timers = [];
    const leaky = [];
    const settle = (node, { timer, given, leaks }) => {
      if (timer && !given) context.report({ node, message });
      else if (leaks.length) leaky.push({ node, leaks });
    };
    // the member names a chain reads on its way down to its root: `pending.get(1).rej(e)` reads rej, get
    const namesOf = n => {
      const names = [];
      for (n = inner(n); n.type === "MemberExpression" || n.type === "CallExpression"; n = inner(n.type === "CallExpression" ? n.callee : n.object)) {
        if (n.type === "MemberExpression") names.push(nameOf(n.computed, n.property));
      }
      return names;
    };
    // a call that is only the start of a longer chain: `pending.get(1)` in `pending.get(1).rej(e)`
    const continues = n => {
      const o = outer(n);
      const p = o.parent;
      return (p.type === "MemberExpression" && p.object === o) || (p.type === "CallExpression" && p.callee === o);
    };
    // does a timer callback call something out of one of these containers? A chain that reads a
    // name the stored value does not run under (`.rej` on `{ res, rej }`) is not it.
    const runs = (cb, leaks) => {
      cb = inner(cb);
      const fn = cb.type === "Identifier" ? executor(cb) : null;
      const top = fn && FNS.has(fn.type) ? fn : cb;
      const runsAt = c => {
        const root = rootOf(c);
        if (!root) return false;
        const names = namesOf(c);
        return !BENIGN.has(names[0]) && leaks.some(l => l.root === root && !names.some(x => l.skip.has(x)));
      };
      if (runsAt(top)) return true;
      for (const n of nodes(top)) {
        // `for (const f of rs) f()`
        if (n.type === "ForOfStatement" && leaks.some(l => l.root === rootOf(n.right))) return true;
        if (n.type === "CallExpression" && !continues(n) && runsAt(n)) return true;
      }
      return false;
    };
    // a promise executor: `new P(exec)`, `super(exec)` in a subclass, `Reflect.construct(P, [exec])`
    const check = (node, arg) => {
      const exec = executor(arg && inner(arg));
      if (!exec || !FNS.has(exec.type)) return;
      // `(r = noop) => ...` still has the resolver in `r`
      const first = exec.params[0]?.type === "AssignmentPattern" ? exec.params[0].left : exec.params[0];
      if (first?.type !== "Identifier") return;
      const resolver = declared(exec, v => v.defs.some(d => d.type === "Parameter" && d.name === first));
      settle(node, analyze(exec, resolver));
    };
    return {
      NewExpression(node) {
        check(node, node.arguments[0]);
      },
      CallExpression(node) {
        const c = inner(node.callee);
        const args = timerArgs(node);
        if (args) timers.push(args);
        if (c.type === "Super") return check(node, node.arguments[0]);
        const how = c.type === "MemberExpression" ? nameOf(c.computed, c.property) : c.name;
        // `promisify(setTimeout)` is a sleep helper; so is `util.promisify(t)` for any alias t
        if (how === "promisify" && node.arguments[0] && isTimerFn(node.arguments[0])) {
          context.report({ node, message: ban("promisified timers") });
        } else if (how === "construct" && c.object?.name === "Reflect") {
          const list = node.arguments[1] && inner(node.arguments[1]);
          if (list?.type === "ArrayExpression") check(node, list.elements[0]);
        }
        // `const { resolve } = Promise.withResolvers()`, `const w = Promise.withResolvers()`,
        // and the same assigned later: `w = Promise.withResolvers()`, `({ resolve } = ...)`
        if (how !== "withResolvers" || c.type !== "MemberExpression") return;
        const top = outer(node);
        const d = top.parent;
        let id = null;
        let obj = false;
        if (d.type === "VariableDeclarator" && d.init === top) id = d.id;
        else if (d.type === "AssignmentExpression" && d.right === top && d.operator === "=") id = d.left;
        else return;
        let v = null;
        if (id.type === "Identifier") {
          v = d.type === "VariableDeclarator" ? declared(d, x => x.name === id.name) : lookup(id);
          obj = true;
        } else if (id.type === "ObjectPattern") {
          const prop = id.properties.find(x => x.type === "Property" && !x.computed && x.key.name === "resolve");
          const target = prop?.value.type === "AssignmentPattern" ? prop.value.left : prop?.value;
          if (target?.type === "Identifier") v = d.type === "VariableDeclarator" ? declared(d, x => x.name === target.name) : lookup(target);
        }
        if (v) settle(node, analyze(scopeOf(d), v, obj));
      },
      "Program:exit"() {
        for (const { node, leaks } of leaky) if (timers.some(a => a[0] && runs(a[0], leaks))) context.report({ node, message });
      },
    };
  },
};

// Fixed waits that never build a promise in the test body: a browser driver's
// waitForTimeout (any receiver, destructured, passed on, quoted or const key), a
// timer inside a script string handed to the browser, and a busy loop on the clock
// (no await and no call in its body, so it only burns the thread until the time is up).
const SCRIPT_RUNNERS = new Set(["evaluate", "evaluateHandle", "waitForFunction", "addInitScript", "$eval", "$$eval"]);
const NOW = new Set(["Date.now", "performance.now"]);
const noFixedWait = {
  meta: { type: "problem", schema: [] },
  create(context) {
    const src = context.sourceCode;
    const keyOf = (computed, k) => keyIn(src, computed, k);
    const flag = (node, what) => context.report({ node, message: ban(what) });
    // text of a script argument: a string, a template, or an object holding one (`{ content }`)
    const mentionsTimer = a => {
      if (a.type === "Literal") return typeof a.value === "string" && /set(Timeout|Interval)/.test(a.value);
      if (a.type === "TemplateLiteral") return a.quasis.some(q => /set(Timeout|Interval)/.test(q.value.cooked ?? q.value.raw));
      if (a.type === "ObjectExpression") return a.properties.some(x => x.type === "Property" && mentionsTimer(x.value));
      return false;
    };
    const busy = node => {
      const clock = n => n.type === "CallExpression" && n.callee.type === "MemberExpression" && NOW.has(`${n.callee.object.name}.${n.callee.property.name}`);
      if (![...nodes(node.test ?? node)].some(clock)) return;
      const rest = [node.body, node.update].filter(Boolean).flatMap(x => [...nodes(x)]);
      if (!rest.some(n => /^(Await|Yield|Call|New|TaggedTemplate|Import)/.test(n.type))) flag(node, "busy-waits on the clock");
    };
    return {
      MemberExpression(n) {
        if (keyOf(n.computed, n.property) === "waitForTimeout") flag(n, "fixed waitForTimeout (a call, a reference or a destructure of it)");
      },
      Property(n) {
        if (n.parent.type === "ObjectPattern" && keyOf(n.computed, n.key) === "waitForTimeout") flag(n, "fixed waitForTimeout (a call, a reference or a destructure of it)");
      },
      CallExpression(n) {
        const c = n.callee;
        if (c.type === "MemberExpression" && SCRIPT_RUNNERS.has(keyOf(c.computed, c.property)) && n.arguments.slice(0, 2).some(mentionsTimer)) {
          flag(n, "timers in a script string (it runs in the browser, where the sleep rule cannot see it)");
        }
      },
      WhileStatement: busy,
      DoWhileStatement: busy,
      ForStatement: busy,
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
    files: ["tests/**/*.ts"],
    plugins: { local: { rules: { "no-sleep-promise": noSleepPromise, "no-fixed-wait": noFixedWait } } },
    rules: {
      "local/no-sleep-promise": "error",
      "local/no-fixed-wait": "error",
      "no-restricted-imports": ["error", {
        paths: TIMERS_MODULES.map(name => ({ name, message: NO_TIMERS })),
      }],
      "no-restricted-syntax": ["error",
        {
          selector: "CallExpression[callee.object.name='Atomics'][callee.property.name=/^wait(Async)?$/]",
          message: ban("Atomics.wait (it blocks for a fixed time)"),
        },
        {
          // scheduler.wait(ms) is the timers/promises sleep, also reachable as a global in some runtimes
          selector: "CallExpression[callee.property.name='wait']:matches([callee.object.name='scheduler'], [callee.object.property.name='scheduler'], [callee.object.property.value='scheduler'])",
          message: ban("scheduler.wait"),
        },
        {
          selector: `ImportExpression${isTimersModule("source")}`,
          message: NO_TIMERS,
        },
        {
          selector: `CallExpression:matches(${REQUIRES.join(", ")})${isTimersModule("arguments.0")}`,
          message: NO_TIMERS,
        },
      ],
    },
  },
];
