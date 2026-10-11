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
const REQUIRES = ["", ".expression", ".expressions.1", ".expressions.1.expression"].flatMap(w => [
  `[callee${w}.name='require']`,
  ...["require", "getBuiltinModule"].flatMap(m => [`[callee${w}.property.name='${m}']`, `[callee${w}.property.value='${m}']`]),
  `[callee${w}.callee.name='createRequire']`, `[callee${w}.callee.property.name='createRequire']`]);
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
// array methods that hand each element to a callback as its first argument
const ITER = new Set(["forEach", "map", "filter", "some", "every", "find", "findLast", "findIndex", "flatMap"]);
// calls that subscribe the resolver to something that will run it later: the real signal of a race
const SUBSCRIBES = new Set(["on", "once", "addListener", "prependListener", "prependOnceListener", "addEventListener", "then", "finally", "subscribe"]);

// The scope manager's view of a value: does `e`, read down `path`, end at a host function that
// `leaf(name, path, local)` accepts? Follows consts, destructuring, objects, arrays, defaults,
// `??`/`||`/ternary and `.bind`. `local` is true for a name the file declares itself.
const makeResolver = (src, leaf, state = { cuts: 0 }) => {
  const lookup = node => lookupIn(src, node);
  const keyOf = (computed, k) => keyIn(src, computed, k);
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
  // `state.cuts` counts every walk a cycle ended early, here and in the helper analysis.
  
  const known = new Map();
  const reach = (e, path, seen) => {
    e = inner(e);
    const key = `${e.type}${e.range}|${path}`;
    if (known.has(key)) return known.get(key);
    if (seen.has(key)) { state.cuts++; return false; }
    seen.add(key);
    const before = state.cuts;
    const r = walk(e, path, seen);
    seen.delete(key);
    if (r || state.cuts === before) known.set(key, r);
    return r;
  };
  const walk = (e, path, seen) => {
    switch (e.type) {
      case "Identifier": {
        const def = lookup(e)?.defs;
        // a name the file declares itself is no host object, but an import is the real thing
        if (leaf(e.name, path, !!def?.length && def[0].type !== "ImportBinding")) return true;
        if (def?.length !== 1) return false;
        let pat, init;
        if (def[0].type === "Variable" && def[0].parent.kind === "const") ({ id: pat, init } = def[0].node);
        else if (def[0].type === "Parameter") pat = def[0].node.params?.find(x => x.range[0] <= def[0].name.range[0] && def[0].name.range[1] <= x.range[1]);
        const at = pat && locate(pat, def[0].name);
        if (!at) return false;
        return !!(init && reach(init, [...at.path, ...path], seen)) || !!(at.dflt && reach(at.dflt, path, seen));
      }
      case "MemberExpression": {
        const k = keyOf(e.computed, e.property);
        return k !== undefined && reach(e.object, [k, ...path], seen);
      }
      case "ObjectExpression":
        if (!path.length) return false;
        // the last property that names the key wins; a spread could hide any key
        for (const p of [...e.properties].reverse()) {
          if (p.type !== "Property") return false;
          if (String(nameOf(p.computed, p.key)) === String(path[0])) return reach(p.value, path.slice(1), seen);
        }
        return false;
      case "ArrayExpression": {
        const i = path[0];
        if (typeof i !== "number" || i >= e.elements.length || e.elements.slice(0, i + 1).some(x => !x || x.type === "SpreadElement")) return false;
        return reach(e.elements[i], path.slice(1), seen);
      }
      case "LogicalExpression":
        return reach(e.left, path, seen) || reach(e.right, path, seen);
      case "ConditionalExpression":
        return reach(e.consequent, path, seen) || reach(e.alternate, path, seen);
      case "CallExpression":
        return !path.length && methodOn(e.callee, "bind", seen);
    }
    return false;
  };
  const isFn = c => reach(c, [], new Set());
  // `t.call`, `t.apply`, `t.bind` where t is a timer. `seen` carries the walk that
  // got here, so `const t = t.bind(null)` ends instead of starting over.
  const methodOn = (callee, how, seen = new Set()) => {
    const c = inner(callee);
    return c.type === "MemberExpression" && nameOf(c.computed, c.property) === how && reach(c.object, [], seen);
  };
  return { reach, isFn, methodOn };
};

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
// - a timer, a script, `Atomics.wait` or `scheduler.wait` is passed on as a value (`run(setTimeout as never)`,
//   `run(Atomics.wait)`), or its name is built at runtime (`'set' + name`); a script string is read through
//   consts, templates, `String.raw`, `+`, `.concat` and an array `.join`, and nothing past a call result,
//   a `let` or a parameter;
// - the resolver is wrapped in a literal that is kept in a variable first (`const o = { f: r }; after(o)`),
//   or walked by `reduce` or a `for...of` over a literal instead of `forEach`, `map` and the like;
// - the resolver is run as `r['call']()` or handed over as `setTimeout(r.call, 5)`;
// - a stored resolver (`rs.push(r)`, `rs[0] = r`) is run by a timer without a call rooted at the same
//   container (`const [f] = rs; f()`), or sits behind `this.` or an undeclared name;
// - `Promise.withResolvers()` is kept on a property (`this.d = Promise.withResolvers()`);
// - the timers module is loaded through a stored `createRequire(...)` result (`const req = createRequire(u); req('timers')`);
// - a clock busy-wait calls something (`while (Date.now() < end) { check(); }` is a poll), reads a clock the
//   rule does not know (`process.hrtime`, `Number(new Date())`, `performance.timeOrigin`), or loops on a
//   condition other than the clock or a constant (`while (!done) { if (Date.now() > end) break; }`);
// - the race fallback, which is the one exemption kept: a resolver also handed to a subscription (`on`, `once`,
//   `addListener`, `prependListener`, `addEventListener`, `then`, `finally`, `subscribe`), or stored in a container
//   that code outside every timer callback calls (`handlers.push(r)` plus `handlers.forEach(f => f())` in a
//   listener), is a timeout fallback in a race on a real signal, so it passes. Any other read (`noop(r)`,
//   `expect(r)`, `return r`, a store nobody calls) is not a handoff. A call inside an `if (false)` or `false &&`
//   branch does not count; a condition the rule cannot fold does. A `Promise.withResolvers()` object held in an
//   array, object or logical expression counts as handed off without checking who calls it. Rewrite such a test
//   as a deadline guard that rejects to get strictness.
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
    const state = { cuts: 0 };
    const timerLeaf = (name, path) => (!path.length && TIMERS.has(name)) || (path.length === 1 && GLOBALS.has(name) && TIMERS.has(path[0]));
    const { isFn: isTimerFn, methodOn } = makeResolver(src, timerLeaf, state);
    // `f.apply(this, list)` and `Reflect.apply(f, this, list)`: the function, whether it is a
    // timer, and which argument holds the list
    const applyTarget = call => {
      const c = inner(call.callee);
      if (c.type !== "MemberExpression" || nameOf(c.computed, c.property) !== "apply") return null;
      const o = inner(c.object);
      if (o.type === "Identifier" && o.name === "Reflect" && !lookup(o)?.defs.length) {
        const f = call.arguments[0] && inner(call.arguments[0]);
        return f ? { timer: isTimerFn(f), fn: executor(f), at: 2 } : null;
      }
      return { timer: isTimerFn(o), fn: executor(o), at: 1 };
    };
    // What a timer call hands the timer, as `(callback, ms, ...args)`, or null when the
    // call is no timer: `t(cb, 5)`, `t.call(this, cb, 5)`, `t.apply(this, [cb, 5])`,
    // `t.bind(this)(cb, 5)`, `(0, t)(cb, 5)`.
    const timerArgs = call => {
      const c = inner(call.callee);
      if (c.type === "CallExpression" && methodOn(c.callee, "bind")) return [...c.arguments.slice(1), ...call.arguments];
      if (methodOn(c, "call")) return call.arguments.slice(1);
      const ap = applyTarget(call);
      if (ap?.timer) {
        const list = call.arguments[ap.at] && inner(call.arguments[ap.at]);
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
    const helpers = new Map();
    const analyze = (exec, resolver, obj = false) => {
      const inside = n => n.range[0] >= exec.range[0] && n.range[1] <= exec.range[1];
      const fnsOf = site => {
        const fns = [];
        for (let n = site; n && n !== exec; n = n.parent) if (FNS.has(n.type)) fns.push(n);
        return fns;
      };
      // `if (false) ee.on('x', r)`: a branch that cannot run hands nothing off
      const falsy = t => { t = inner(t); return (t.type === "Literal" && !t.value) || (t.type === "Identifier" && t.name === "undefined"); };
      const truthy = t => { t = inner(t); return t.type === "Literal" && !!t.value; };
      const dead = site => {
        for (let n = site; n && n !== exec && n.parent; n = n.parent) {
          const p = n.parent;
          if ((p.type === "IfStatement" || p.type === "ConditionalExpression") && ((p.consequent === n && falsy(p.test)) || (p.alternate === n && truthy(p.test)))) return true;
          if (p.type === "LogicalExpression" && p.right === n && ((p.operator === "&&" && falsy(p.left)) || (p.operator === "||" && truthy(p.left)))) return true;
        }
        return false;
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
      // The identifier a parameter pattern binds to the value found `via` these keys of the argument:
      // `({ f }) => ...` called with `{ f: r }` binds f.
      const bindAt = (pat, via) => {
        if (!pat) return null;
        if (pat.type === "AssignmentPattern") return bindAt(pat.left, via);
        if (pat.type === "Identifier") return pat;
        if (!via.length) return null;
        const [k, ...rest] = via;
        if (pat.type === "ObjectPattern") {
          for (const q of pat.properties) if (q.type === "Property" && String(keyOf(q.computed, q.key)) === String(k)) return bindAt(q.value, rest);
        } else if (pat.type === "ArrayPattern") return bindAt(pat.elements[k], rest);
        return null;
      };
      // What a helper declared in this file does with parameter `i`, or null when `fn` is not one
      // (imported, a method, already being analyzed). `via`: where in that argument the resolver sits.
      const helperFlow = (fn, i, via = []) => {
        const param = fn && FNS.has(fn.type) ? bindAt(fn.params[i], via) : null;
        if (!param) return null;
        if (busy.has(fn)) { state.cuts++; return null; }
        // one helper and one parameter answer the same for every caller, unless a recursion cut the answer short
        const key = `${fn.range}|${param.range}`;
        if (helpers.has(key)) return helpers.get(key);
        busy.add(fn);
        const before = state.cuts;
        const r = analyze(fn, declared(fn, v => v.defs.some(d => d.type === "Parameter" && d.name === param)));
        busy.delete(fn);
        if (state.cuts === before) helpers.set(key, r);
        return r;
      };
      // ...for a call, as `after(r)`, `after.call(null, r)`, `after.bind(null, r)`
      const helperCall = (call, arg, via) => {
        const c = inner(call.callee);
        const how = c.type === "MemberExpression" ? nameOf(c.computed, c.property) : undefined;
        const i = call.arguments.indexOf(arg);
        if ((how === "call" || how === "bind") && i > 0) return helperFlow(executor(inner(c.object)), i - 1, via);
        return helperFlow(executor(c), i, via);
      };

      // How is the value of expression `e` consumed?
      const trace = (e, via = []) => {
        const out = none();
        // `listen`: handed to a subscription. `store`: kept in the containers `roots` names, for
        // code elsewhere to run. `use`, `call`: any other read. Inside a nested function, only
        // a function that is itself given (to a subscription) or stored (in a container) counts.
        const hit = (kind, site, roots = []) => {
          const fns = fnsOf(site);
          const flows = fns.map(fnFlow);
          if (kind === "timer" || flows.some(x => x.timer)) out.timer = true;
          if (kind === "timer" || dead(site)) return;
          const owned = flows.some(x => x.given);
          const carried = flows.flatMap(x => x.leaks);
          out.leaks.push(...carried);
          if (owned || (kind === "listen" && !fns.length)) out.given = true;
          if (kind === "store" && (!fns.length || owned || carried.length)) out.leaks.push(...roots);
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
            else if (call && applyTarget(p)?.timer && p.arguments[applyTarget(p).at] === e) hit("timer", p);
            // the callback, or an argument the timer passes to it (`setTimeout(go, 5, r)`)
            else if (args) { if (args[0] === e || args.indexOf(e) > 1) hit("timer", p); }
            // `t.bind(null, r, 5)` keeps the arguments for later
            else if (call && methodOn(p.callee, "bind")) { const i = p.arguments.indexOf(e); if (i === 1 || i > 2) hit("timer", p); }
            else if (!isConsole(p)) {
              const f = call ? helperCall(p, e, via) : null;
              const m = call && inner(p.callee);
              const name = m.type === "MemberExpression" ? nameOf(m.computed, m.property) : undefined;
              if (f) {
                if (f.timer) hit("timer", p);
                if (f.given) hit("listen", p);
                if (f.leaks.length) hit("store", p, f.leaks);
              }
              if (!f?.timer) {
                if (SUBSCRIBES.has(name)) hit("listen", p);
                else if (STORES.has(name) && rootOf(m.object)) hit("store", p, [{ root: rootOf(m.object), skip: new Set() }]);
                else {
                  // `setTimeout(once(r), 5)`: the call only wraps the resolver for the timer
                  const t = trace(p);
                  if (t.timer && !t.given) hit("timer", p);
                  else merge(out, t);
                  hit("use", p);
                }
              }
            }
            break;
          }
          case "AssignmentExpression": {
            if (p.right !== e) break;
            const v = p.left.type === "Identifier" ? lookup(p.left) : null;
            if (v?.defs[0] && inside(v.defs[0].name)) merge(out, follow(sameObj(e, v)));
            else hit("store", p, rootOf(p.left) ? [{ root: rootOf(p.left), skip: new Set() }] : []);
            break;
          }
          case "VariableDeclarator":
            if (p.init === e && p.id.type === "Identifier") merge(out, follow(sameObj(e, declared(p, v => v.name === p.id.name))));
            break;
          case "ReturnStatement":
            hit("use", p);
            break;
          case "ArrowFunctionExpression":
            if (p.body === e) hit("use", p);
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
              merge(out, except(trace(p.parent, [nameOf(p.computed, p.key), ...via]), p.parent.properties.filter(x => x !== p && x.type === "Property").map(x => nameOf(x.computed, x.key)).filter(k => k !== undefined && k !== nameOf(p.computed, p.key))));
            }
            break;
          case "MemberExpression": {
            // the resolver in a container: `q[0]`, `rec.resolve`, `q.shift()`
            const name = nameOf(p.computed, p.property);
            if (p.object !== e || INERT.has(name)) break;
            if (p.parent.type !== "CallExpression" || p.parent.callee !== p) merge(out, trace(p));
            else if (TAKES.has(name)) merge(out, trace(p.parent));
            else if (ITER.has(name)) {
              // `[r].forEach((f) => setTimeout(f, 50))`: the callback gets each element
              const f = helperFlow(executor(p.parent.arguments[0]), 0);
              if (f?.timer) hit("timer", p.parent);
              if (f?.given) hit("listen", p.parent);
              if (f?.leaks.length) hit("store", p.parent, f.leaks);
            }
            break;
          }
          case "ArrayExpression": {
            // `setTimeout.apply(null, [r, 5])`: the first element is the callback
            const call = p.parent;
            const ap = call.type === "CallExpression" ? applyTarget(call) : null;
            const i = p.elements.indexOf(e);
            if (ap && call.arguments[ap.at] === p) {
              if (ap.timer) { if (i === 0 || i > 1) hit("timer", call); }
              else {
                const f = helperFlow(ap.fn, i, via);
                if (f?.timer) hit("timer", call);
                if (f?.given) hit("listen", call);
                if (f?.leaks.length) hit("store", call, f.leaks);
              }
            } else merge(out, trace(p, [i, ...via]));
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

    // timers and calls in the file, and promises that are not settled by what they do alone (judged at the end)
    const timers = [];
    const calls = [];
    const pending = [];
    const settle = (node, { timer, given, leaks }) => {
      if (given || !(timer || leaks.length)) return;
      if (timer && !leaks.length) context.report({ node, message });
      else pending.push({ node, leaks, timer });
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
    // What the timer callbacks of the file call, by container: every chain that starts at a
    // variable, as the member names it reads. Built once, so a promise that stored its resolver
    // costs a lookup and not a walk of every callback.
    let tops = null;
    const topsOf = () => {
      if (tops) return tops;
      tops = new Set();
      for (const a of timers) {
        const cb = a[0] && inner(a[0]);
        if (!cb) continue;
        const fn = cb.type === "Identifier" ? executor(cb) : null;
        tops.add(fn && FNS.has(fn.type) ? fn : cb);
      }
      return tops;
    };
    let ran = null;
    const ranOf = () => {
      if (ran) return ran;
      ran = new Map();
      const add = (root, names) => {
        const k = names.join(".");
        if (!ran.has(root)) ran.set(root, new Map());
        ran.get(root).set(k, names);
      };
      for (const top of topsOf()) {
        const chain = c => { const root = rootOf(c); if (root) add(root, namesOf(c)); };
        chain(top);
        for (const n of nodes(top)) {
          // `for (const f of rs) f()`
          if (n.type === "ForOfStatement") { const root = rootOf(n.right); if (root) add(root, []); }
          if (n.type === "CallExpression" && !continues(n)) chain(n);
        }
      }
      return ran;
    };
    // does a timer call something out of one of these containers? A chain that reads a name the
    // stored value does not run under (`.rej` on `{ res, rej }`) is not it.
    const runs = leaks => leaks.some(l => {
      for (const names of ranOf().get(l.root)?.values() ?? []) {
        if (!BENIGN.has(names[0]) && !names.some(x => l.skip.has(x))) return true;
      }
      return false;
    });
    // The same, for the calls outside every timer callback: someone besides the timer runs the container.
    let called = null;
    const calledOf = () => {
      if (called) return called;
      called = new Map();
      const ts = [...topsOf()];
      for (const n of calls) {
        if (ts.some(t => n.range[0] >= t.range[0] && n.range[1] <= t.range[1])) continue;
        const root = rootOf(n.type === "ForOfStatement" ? n.right : n);
        if (!root || (n.type === "CallExpression" && continues(n))) continue;
        if (!called.has(root)) called.set(root, []);
        called.get(root).push(n.type === "ForOfStatement" ? [] : namesOf(n));
      }
      return called;
    };
    const handedOff = leaks => leaks.some(l => (calledOf().get(l.root) ?? []).some(names => !STORES.has(names[0]) && !BENIGN.has(names[0]) && !names.some(x => l.skip.has(x))));
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
      ForOfStatement(node) {
        calls.push(node);
      },
      CallExpression(node) {
        calls.push(node);
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
        for (const { node, leaks, timer } of pending) if ((timer || runs(leaks)) && !handedOff(leaks)) context.report({ node, message });
      },
    };
  },
};

// Fixed waits that never build a promise in the test body: a browser driver's
// waitForTimeout (any receiver, destructured, passed on, quoted or const key), a
// timer inside a script string handed to the browser, and a busy loop on the clock
// (no await and no call in its body, so it only burns the thread until the time is up).
// `Atomics.wait` blocks the thread for a fixed time, `scheduler.wait` is the timers/promises sleep.
// Both are found through the same alias following as the timers: `globalThis.Atomics.wait`,
// `Atomics['wait']`, `const { wait } = Atomics`, `const A = Atomics`, `(0, Atomics.wait)(...)`.
// A name the file declares itself (`const scheduler = makeSched()`) is no host object, and
// `app.scheduler.wait(job)` is somebody else's scheduler.
const onHost = leaf => (name, path, local) => leaf(name, path, local) || (GLOBALS.has(name) && !local && path.length > 0 && leaf(path[0], path.slice(1), false));
const WAITS = [
  [onHost((name, path, local) => name === "Atomics" && !local && path.length === 1 && /^wait(Async)?$/.test(String(path[0]))), "Atomics.wait (it blocks for a fixed time)"],
  [onHost((name, path, local) => name === "scheduler" && !local && path.length === 1 && path[0] === "wait"), "scheduler.wait"],
];
const SCRIPT_RUNNERS = new Set(["evaluate", "evaluateHandle", "waitForFunction", "addInitScript", "$eval", "$$eval"]);
// a clock read: `Date.now`, `performance.now`, in any of the spellings the timers have (host object,
// quoted key, alias, destructure, comma, `?.`); `new Date()` with no argument is the current time too
const clockLeaf = onHost((name, path, local) => !local && path.length === 1 && path[0] === "now" && (name === "Date" || name === "performance"));
const noFixedWait = {
  meta: { type: "problem", schema: [] },
  create(context) {
    const src = context.sourceCode;
    const keyOf = (computed, k) => keyIn(src, computed, k);
    const flag = (node, what) => context.report({ node, message: ban(what) });
    const waits = WAITS.map(([leaf, what]) => [makeResolver(src, leaf), what]);
    // The text a script argument holds, as far as the file spells it out: a string, a template, a
    // `String.raw` template, a `+` or `.concat` of those, a const that holds one, an array `.join`ed, an
    // object holding one (`{ content }`). What it cannot read becomes a NUL, so two readable halves
    // still join (`'set' + 'Timeout'`) and an unknown middle does not.
    const textOf = (e, depth = 0) => {
      e = inner(e);
      const unknown = "\0";
      if (depth > 8) return unknown;
      const sub = x => textOf(x, depth + 1);
      switch (e.type) {
        case "Literal": return typeof e.value === "string" ? e.value : String(e.value);
        case "TemplateLiteral":
        case "TaggedTemplateExpression": {
          const t = e.type === "TemplateLiteral" ? e : e.quasi;
          return t.quasis.map((q, i) => (q.value.cooked ?? q.value.raw) + (i < t.expressions.length ? sub(t.expressions[i]) : "")).join("");
        }
        case "BinaryExpression": return e.operator === "+" ? sub(e.left) + sub(e.right) : unknown;
        case "ConditionalExpression": return `${sub(e.consequent)}${unknown}${sub(e.alternate)}`;
        case "LogicalExpression": return `${sub(e.left)}${unknown}${sub(e.right)}`;
        case "ObjectExpression": return e.properties.map(x => (x.type === "Property" ? sub(x.value) : unknown)).join(unknown);
        case "ArrayExpression": return e.elements.map(x => (x ? sub(x) : "")).join(unknown);
        case "Identifier": {
          const def = lookupIn(src, e)?.defs;
          const d = def?.length === 1 && def[0].type === "Variable" && def[0].parent.kind === "const" ? def[0].node : null;
          return d?.id.type === "Identifier" && d.init ? sub(d.init) : unknown;
        }
        case "CallExpression": {
          const c = inner(e.callee);
          const how = c.type === "MemberExpression" ? keyOf(c.computed, c.property) : undefined;
          if (how === "concat") return sub(c.object) + e.arguments.map(sub).join("");
          if (how === "join" && inner(c.object).type === "ArrayExpression") {
            const sep = e.arguments[0] ? sub(e.arguments[0]) : ",";
            return inner(c.object).elements.map(x => (x ? sub(x) : "")).join(sep);
          }
        }
      }
      return unknown;
    };
    const mentionsTimer = a => /set(Timeout|Interval)/.test(textOf(a));
    const clock = makeResolver(src, clockLeaf);
    const isClock = n => {
      if (n.type === "NewExpression") {
        const c = inner(n.callee);
        return c.type === "Identifier" && c.name === "Date" && !n.arguments.length && !src.getScope(n).set.get("Date")?.defs.length;
      }
      if (n.type !== "CallExpression") return false;
      const f = inner(n.callee);
      if (clock.isFn(f) || clock.methodOn(f, "call") || clock.methodOn(f, "apply")) return true;
      // `new Date().getTime()`
      return f.type === "MemberExpression" && ["getTime", "valueOf"].includes(keyOf(f.computed, f.property)) && isClock(inner(f.object));
    };
    // A busy loop reads the clock in its test, or loops forever on a clock read in its body, and
    // does nothing else on a pass: no await, yield, call, new or import besides the clock read itself.
    const busy = node => {
      const test = node.test && inner(node.test);
      const forever = !test || (test.type === "Literal" && !!test.value);
      const clocked = forever ? [...nodes(node.body)].some(isClock) : [...nodes(test)].some(isClock);
      if (!clocked) return;
      const rest = [node.body, node.update].filter(Boolean).flatMap(x => [...nodes(x)]);
      if (!rest.some(n => !isClock(n) && /^(Await|Yield|Call|New|TaggedTemplate|Import)/.test(n.type))) flag(node, "busy-waits on the clock");
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
        const f = inner(c);
        for (const [w, what] of waits) if (w.isFn(f) || w.methodOn(f, "call") || w.methodOn(f, "apply")) flag(n, what);
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
