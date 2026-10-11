// The message tail every ban ends with; the tests import it so the wording lives in one place.
export const SIGNALS = 'Wait on a signal instead: vi.waitFor, fake timers, or an awaited event.';

// Work done, counted for the cost test: it cannot time a lint on a busy host, and a count is the same on every run. Every unwrap, scope lookup
// and read of a name's writes, every step of a walk and every node it visits adds one. A no-op unless a test sets globalThis.__sleepOps to a
// number, and on globalThis because ESLint loads the config as a module instance of its own.
const tick = (n = 1) => {
  if (typeof globalThis.__sleepOps === 'number') globalThis.__sleepOps += n;
};

const TIMER_HOSTS = new Set(['globalThis', 'window', 'self', 'global']);
// setInterval in an executor can resolve on a schedule just like setTimeout.
const TIMER_NAMES = ['setTimeout', 'setInterval'];

// Casts, `!`, `?.` and a comma do not change what runs: `(globalThis as any).setTimeout`, `(setTimeout as T)(...)`,
// `setTimeout!`, `(0, setTimeout)(...)`.
function unwrap(node) {
  tick();
  for (;;) {
    if (/^(TSAsExpression|TSNonNullExpression|TSTypeAssertion|TSSatisfiesExpression|ChainExpression)$/.test(node.type)) node = node.expression;
    else if (node.type === 'SequenceExpression') node = node.expressions.at(-1);
    else return node;
  }
}

// A function with a body. Not `TSFunctionType` in `(f: () => void)` or an overload signature, which have none.
const FN = /^(FunctionDeclaration|FunctionExpression|ArrowFunctionExpression)$/;

// The rule being run, so keyOf can read a `const k = 'setTimeout'` key through its scope.
// ESLint runs one file at a time on a thread and creates every rule before it visits.
let current;

// 'x' in `a['x']` and ``a[`x`]``; a number index comes back as its string.
function literalKey(node) {
  node = unwrap(node);
  if (node.type === 'Literal') return typeof node.value === 'string' || typeof node.value === 'number' ? String(node.value) : undefined;
  if (node.type === 'TemplateLiteral' && !node.expressions.length) return node.quasis[0].value.cooked;
  return undefined;
}

// Every direct write to a variable: its declaration's init, `x = v`, `x ||= v`, a default (`(x = v) => ...`).
// null marks a write the lint cannot read (destructuring, `x += 1`, `for (x of xs)`), or a default no call ever uses.
// Answered once per variable: a name written N times is asked about by every walk that reaches it.
const writeMemo = new WeakMap();
function writes(variable) {
  if (writeMemo.has(variable)) return writeMemo.get(variable);
  tick(variable.references.length + 1);
  const all = variable.references
    .filter((ref) => ref.isWrite())
    .map(({ identifier: id }) => {
      const p = id.parent;
      if (p.type === 'VariableDeclarator' && p.id === id) return p.init ?? null;
      if (p.type === 'AssignmentExpression' && p.left === id && /^(=|\|\|=|&&=|\?\?=)$/.test(p.operator)) return p.right;
      if (p.type === 'AssignmentPattern' && p.left === id) return defaultLive(p) ? p.right : null;
      return null;
    });
  writeMemo.set(variable, all);
  return all;
}

// Whether any value `root` can hold is one `spec.leaf` accepts, through `||`, `??`, `?:` and the writes of each name it reaches. An explicit
// stack, not recursion: a chain of N copies is N levels, and a throw aborts the lint run. `leaf(node, variable)` answers true (a hit),
// false (a dead end), a node (keep looking there) or undefined (the default: look through `||`, `??`, `?:` and into a name). `direct`
// answers for a name from its references, `more` lists further nodes a name leads to. A name on the way to a hit is recorded true in
// `memo`; the caller records the misses, once a whole query has failed.
function reach(root, { seen, memo, leaf, direct, more }) {
  const via = new Map();
  const stack = [[root, null]];
  const hit = (owner) => {
    for (let v = owner; v; v = via.get(v)) memo?.set(v, true);
    return true;
  };
  while (stack.length) {
    const [raw, owner] = stack.pop();
    tick();
    const node = raw && unwrap(raw);
    if (!node) continue;
    const variable = node.type === 'Identifier' && current ? variableOf(current, node) : null;
    const verdict = leaf(node, variable);
    if (verdict === true) return hit(owner);
    if (verdict === false) continue;
    if (verdict) {
      stack.push([verdict, owner]);
      continue;
    }
    if (node.type === 'LogicalExpression') stack.push([node.right, owner], [node.left, owner]);
    else if (node.type === 'ConditionalExpression') stack.push([node.alternate, owner], [node.consequent, owner]);
    else if (variable) {
      if (memo?.has(variable)) {
        if (memo.get(variable)) return hit(owner);
        continue;
      }
      if (seen.has(variable)) continue;
      seen.add(variable);
      via.set(variable, owner);
      if (direct?.(variable)) return hit(variable);
      const next = [...writes(variable), ...(more?.(variable) ?? [])];
      for (let i = next.length - 1; i >= 0; i--) if (next[i]) stack.push([next[i], variable]);
    }
  }
  return false;
}

// A parameter default only runs when a call leaves the argument out, or passes `undefined` or `void x`, which the default replaces.
// A function declared in this file whose every call passes the argument never uses its default
// (`function run(s = 'setTimeout(...)')` called as `run('title')`).
// Anything else (exported, passed as a value, never called, one call that leaves it out) keeps the default live.
// An argument that may be `undefined` (`pick ? undefined : 'x'`, `a ?? undefined`) may leave it out.
function leavesOut(arg) {
  return reach(arg, {
    seen: new Set(),
    leaf(node) {
      if (node.type === 'UnaryExpression') return node.operator === 'void';
      return node.type === 'Identifier' && node.name === 'undefined' ? true : undefined;
    },
  });
}
const exported = (node) => /^Export/.test(node?.parent?.type ?? '');
// A call that passes the parameter on (`poll(s, n - 1)`) asks about the parameter's own default while it is being answered: that
// call may be handing the default back, so the default stays live.
// A TypeScript `this` parameter is not an argument: `function after(this: void, f)` takes `f` first.
const paramsOf = (fn) => fn.params.filter((p) => !(p.type === 'Identifier' && p.name === 'this'));
const asking = new Set();
function defaultLive(pattern) {
  if (asking.has(pattern)) return true;
  asking.add(pattern);
  try {
    return defaultRuns(pattern);
  } finally {
    asking.delete(pattern);
  }
}
function defaultRuns(pattern) {
  const fn = pattern.parent;
  const at = FN.test(fn.type) ? paramsOf(fn).indexOf(pattern) : -1;
  if (at < 0 || !current) return true;
  const name = fn.type === 'FunctionDeclaration' ? fn.id : fn.parent.type === 'VariableDeclarator' && fn.parent.init === fn ? fn.parent.id : null;
  // `export function run(s = ...)` and `export const run = (s = ...) => ...` are called by code this file cannot see.
  if (exported(fn.type === 'FunctionDeclaration' ? fn : fn.parent.parent)) return true;
  const variable = name?.type === 'Identifier' ? variableOf(current, name) : null;
  if (!variable) return true;
  const uses = variable.references.filter((ref) => !ref.init);
  const passes = (ref) => {
    const call = ref.identifier.parent;
    if (call.type !== 'CallExpression' || call.callee !== ref.identifier) return false;
    const arg = call.arguments[at] && unwrap(call.arguments[at]);
    return !!arg && !call.arguments.slice(0, at + 1).some((a) => a.type === 'SpreadElement') && !leavesOut(arg);
  };
  return !(uses.length && uses.every(passes));
}

// What a name was set to, when it is set once: a const, or a let, var or parameter default with a single plain write
// (`let k = 'setTimeout'`). Written twice, it holds different values at different times and names nothing.
function constInit(ident) {
  ident = unwrap(ident);
  const variable = current && ident.type === 'Identifier' ? variableOf(current, ident) : null;
  const all = variable ? writes(variable) : [];
  return all.length === 1 ? all[0] : null;
}

// Every write of a name that the lint can read. A ban judges all of them: `let k = 'title'; k = 'waitForTimeout'` names
// a driver key whichever write runs last. A write it cannot read (`k += 'x'`, `k = pick()`) names nothing.
function constInits(ident) {
  ident = unwrap(ident);
  const variable = current && ident.type === 'Identifier' ? variableOf(current, ident) : null;
  return variable ? writes(variable).filter(Boolean) : [];
}

// `k` in `a[k]` when it is a const holding a literal.
function constKey(ident) {
  const init = constInit(ident);
  return init ? literalKey(init) : undefined;
}

// Every key a computed slot can name: a literal, a template, or a name whose readable writes are literals (also through `||`, `??`, `?:`).
// Each variable is read once (`seen`): `k = k || k` written N times is N reads, not N levels of N branches.
function literalKeys(node, seen = new Set()) {
  const keys = [];
  for (const stack = [node]; stack.length; ) {
    const n = unwrap(stack.pop());
    const lit = literalKey(n);
    if (lit !== undefined) keys.push(lit);
    else if (n.type === 'LogicalExpression') stack.push(n.right, n.left);
    else if (n.type === 'ConditionalExpression') stack.push(n.alternate, n.consequent);
    else if (n.type === 'Identifier') {
      const variable = current ? variableOf(current, n) : null;
      if (!variable || seen.has(variable)) continue;
      seen.add(variable);
      stack.push(...writes(variable).filter(Boolean).reverse());
    }
  }
  return keys;
}

// The one key a slot names, for naming a place (`rs.0`); a name written twice has none. A ban uses keysOf.
const keyOf = (member) => (member.computed ? (literalKey(member.property) ?? constKey(member.property)) : member.property.name);
const keysOf = (member) => (member.computed ? literalKeys(member.property) : [member.property.name]);
const keyIs = (member, re) => keysOf(member).some((k) => re.test(k));

// The key of an object-literal or destructuring property: `{ a }`, `{ 'a': x }`, `{ ['a']: x }`, `{ [k]: x }`.
const propKey = (prop) => (prop.computed || prop.key.type === 'Literal' ? (literalKey(prop.key) ?? constKey(prop.key)) : prop.key.name);
const propKeys = (prop) => (prop.computed || prop.key.type === 'Literal' ? literalKeys(prop.key) : [prop.key.name]);

// What a destructuring pattern takes its values from: `const { a } = src`, `({ a } = src)`, `({ a } = src) => ...`.
const sourceOf = (pattern) => {
  const owner = pattern.parent;
  if (owner.type === 'VariableDeclarator') return owner.id === pattern ? owner.init : null;
  return (owner.type === 'AssignmentExpression' || owner.type === 'AssignmentPattern') && owner.left === pattern ? owner.right : null;
};

// The property that binds `id` (`{ a: id }`, `{ a: id = 1 }`) and the pattern it sits in; null for any other write.
function boundBy(id) {
  let node = id;
  if (node.parent.type === 'AssignmentPattern' && node.parent.left === node) node = node.parent;
  const prop = node.parent;
  return prop.type === 'Property' && prop.value === node && prop.parent.type === 'ObjectPattern' ? { prop, pattern: prop.parent } : null;
}

// A pattern that takes its values off a host: `const { a } = globalThis`, `({ a } = window as X)`, `function f({ a } = self)`, a host held in a
// const (`const g = globalThis; const { a } = g`), or one nested under a host key (`const { window: { a } } = globalThis`).
function fromHost(pattern, seen = new Set()) {
  return hostSources(pattern).some((source) => isHost(source, seen));
}
// What a pattern could take its values off: its own source and, under a host key, the source of the pattern it is nested in.
function hostSources(pattern) {
  const out = [];
  for (;;) {
    const source = sourceOf(pattern);
    if (source && (pattern.parent.type !== 'AssignmentPattern' || defaultLive(pattern.parent))) out.push(source);
    const node = pattern.parent.type === 'AssignmentPattern' && pattern.parent.left === pattern ? pattern.parent : pattern;
    const prop = node.parent;
    if (!(prop.type === 'Property' && prop.value === node && prop.parent.type === 'ObjectPattern' && propKeys(prop).some((k) => TIMER_HOSTS.has(k)))) return out;
    pattern = prop.parent;
  }
}

// A global host, behind a cast, a comma, `a ?? b` or `c ? a : b`, or a name set to one (`const g = globalThis`, `const { self: g } = window`).
// A name is answered once: a chain of copies asked about at every call that mentions one would be walked from its end each time. A query that
// finds nothing has read every write of every name it visited, so each of those names is known not to be a host; a name that is one is
// known whatever the walk skipped.
const hostMemo = new WeakMap();
// Keyed by the names joined, since callers pass a fresh array each time.
const hostRefMemo = new Map();
const refMemoFor = (names) => {
  const key = names.join();
  if (!hostRefMemo.has(key)) hostRefMemo.set(key, new WeakMap());
  return hostRefMemo.get(key);
};
function isHost(node, seen) {
  const top = !seen;
  if (top) seen = new Set();
  const found = hostIn(node, seen);
  if (top && !found) for (const variable of seen) hostMemo.set(variable, false);
  return found;
}
function hostIn(node, seen) {
  return reach(node, {
    seen,
    memo: hostMemo,
    leaf(n, variable) {
      if (n.type === 'LogicalExpression' || n.type === 'ConditionalExpression') return undefined;
      if (n.type !== 'Identifier') return false;
      // `self`, `window` and `global` are hosts while nothing in the file declares them, or only an ambient `declare const self: Window` does; a
      // parameter or local of that name is whatever it was given.
      if (TIMER_HOSTS.has(n.name) && (!variable?.defs.length || variable.defs.every((d) => d.node?.parent?.declare))) return true;
      return variable ? undefined : false;
    },
    more: (variable) =>
      variable.references.flatMap((ref) => {
        const bound = ref.isWrite() ? boundBy(ref.identifier) : null;
        return bound && propKeys(bound.prop).some((k) => TIMER_HOSTS.has(k)) ? hostSources(bound.pattern) : [];
      }),
  });
}

// A bare name or a member of a global host (`globalThis.setTimeout`): the only shapes that are the real timer. Behind `??`, `||` and `?:`
// too. For every global but the timers, a name that is a copy counts as well (`const A = Atomics`, `const { scheduler: s } = globalThis`);
// a copy of the timer is the alias rule's. Answered once per name, like isHost.
function isHostRef(node, names, seen) {
  const top = !seen;
  if (top) seen = new Set();
  const found = hostRefIn(node, names, seen);
  if (top && !found) {
    const memo = refMemoFor(names);
    for (const variable of seen) memo.set(variable, false);
  }
  return found;
}
function hostRefIn(node, names, seen) {
  const timer = names.some((name) => TIMER_NAMES.includes(name));
  return reach(node, {
    seen,
    memo: refMemoFor(names),
    leaf(n, variable) {
      if (n.type === 'LogicalExpression' || n.type === 'ConditionalExpression') return undefined;
      if (n.type === 'MemberExpression') return keysOf(n).some((k) => names.includes(k)) && isHost(n.object);
      if (n.type !== 'Identifier') return false;
      if (names.includes(n.name)) return true;
      return timer || !variable ? false : undefined;
    },
    direct: (variable) =>
      variable.references.some((ref) => {
        const bound = ref.isWrite() ? boundBy(ref.identifier) : null;
        return !!bound && propKeys(bound.prop).some((k) => names.includes(k)) && fromHost(bound.pattern);
      }),
  });
}

// `setTimeout.call(globalThis, r, 50)`, `.apply(...)` and `.bind(globalThis)` run the real timer too.
const isBorrowed = (node) => node.type === 'MemberExpression' && keyIs(node, /^(call|apply|bind)$/) && isHostRef(node.object, TIMER_NAMES);

function isTimer(callee) {
  callee = unwrap(callee);
  if (callee.type === 'CallExpression') callee = unwrap(callee.callee);
  // `(fake ?? setTimeout)(r, 50)` and `(pick ? setTimeout : other)(r, 50)` may run the real timer.
  if (callee.type === 'LogicalExpression') return isTimer(callee.left) || isTimer(callee.right);
  if (callee.type === 'ConditionalExpression') return isTimer(callee.consequent) || isTimer(callee.alternate);
  return isHostRef(callee, TIMER_NAMES) || isBorrowed(callee);
}

// `setTimeout` / `globalThis.setTimeout` / `globalThis['setTimeout']` (or setInterval), the shape the alias rule tracks,
// also behind a cast, `a || setTimeout`, `a ?? setTimeout` or `c ? setTimeout : b`.
function isTimerRef(node) {
  node = unwrap(node);
  if (node.type === 'CallExpression') return isBorrowed(unwrap(node.callee)) && keyIs(unwrap(node.callee), /^bind$/);
  if (node.type === 'LogicalExpression') return isTimerRef(node.left) || isTimerRef(node.right);
  if (node.type === 'ConditionalExpression') return isTimerRef(node.consequent) || isTimerRef(node.alternate);
  // A member of a non-host object (`opts.setTimeout`) is a config value or a server method, not the
  // real timer; storing the real timer there is caught where it is parked.
  return isHostRef(node, TIMER_NAMES);
}

// Every node under `node`, depth first. An explicit stack and a per-node cache: the rule asks for the same
// bodies again and again, and a recursive generator costs a frame per level of nesting on every item.
const below = new WeakMap();
function kidsOf(node) {
  tick();
  const kids = [];
  for (const key in node) {
    // The program also carries every token and comment, which are not nodes and can run to hundreds of thousands.
    if (key === 'parent' || key === 'tokens' || key === 'comments' || key === 'loc' || key === 'range') continue;
    const value = node[key];
    if (Array.isArray(value)) {
      for (const child of value) if (child && typeof child.type === 'string') kids.push(child);
    } else if (value && typeof value.type === 'string') kids.push(value);
  }
  return kids;
}
function descendants(node) {
  let out = below.get(node);
  if (out) return out;
  out = [];
  const stack = [node];
  while (stack.length) {
    const cur = stack.pop();
    tick();
    if (cur !== node) out.push(cur);
    const kids = kidsOf(cur);
    for (let i = kids.length - 1; i >= 0; i--) stack.push(kids[i]);
  }
  below.set(node, out);
  return out;
}

// The class a `this` belongs to, and whether it is the static side. An arrow keeps the `this` around it; a plain function has its own.
function classOf(node) {
  for (let n = node.parent; n; n = n.parent) {
    tick();
    if (n.type === 'PropertyDefinition' || n.type === 'MethodDefinition') return { klass: n.parent.parent, isStatic: n.static };
    if (n.type === 'StaticBlock') return { klass: n.parent.parent, isStatic: true };
    if (n.type === 'FunctionDeclaration' || (n.type === 'FunctionExpression' && n.parent.type !== 'MethodDefinition')) return null;
  }
  return null;
}

// What outside code calls a class by: `class A {}`, `const A = class {}`, `A = class {}`.
function staticName(klass) {
  const owner = klass.parent;
  if (klass.type === 'ClassExpression') {
    if (owner.type === 'VariableDeclarator' && owner.id.type === 'Identifier') return owner.id.name;
    if (owner.type === 'AssignmentExpression' && owner.left.type === 'Identifier') return owner.left.name;
  }
  return klass.id?.name ?? null;
}

// `d.resolve`, `rs[0]` -> 'rs.0', `rs[i]` -> 'rs.*'. Parens, casts and `?.` do not change what is named. `this` is the class's own name
// on the static side (`static d` is `A.d` from inside and out).
function pathOf(node) {
  node = unwrap(node);
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'ThisExpression') {
    const inside = classOf(node);
    return (inside?.isStatic && staticName(inside.klass)) || 'this';
  }
  if (node.type !== 'MemberExpression') return null;
  const base = pathOf(node.object);
  return base === null ? null : `${base}.${keyOf(node) ?? '*'}`;
}

// `x.r` and `{ r: 1 }` name a property, not the variable `r`.
const isName = (n) => n.type === 'Identifier' && !(n.parent.property === n && !n.parent.computed) && !(n.parent.key === n && !n.parent.computed);

const isIn = (node, names) => unwrap(node).type === 'Identifier' && names.has(unwrap(node).name);

// The value is one of the names, or an array or object literal holding one (`[r]`, `{ done: r }`): whatever reads it can reach the name.
const holds = (value, names) => {
  value = unwrap(value);
  if (value.type === 'LogicalExpression') return holds(value.left, names) || holds(value.right, names);
  if (value.type === 'ConditionalExpression') return holds(value.consequent, names) || holds(value.alternate, names);
  if (value.type === 'ArrayExpression') return value.elements.some((e) => e && holds(e, names));
  if (value.type === 'ObjectExpression') return value.properties.some((p) => p.type === 'Property' && holds(p.value, names));
  return isIn(value, names);
};

// The names a call argument runs when called, without being that name: `r.bind(null)` runs `r`, `() => r()` and `function () { r(); }` call it.
function wrapperNames(arg) {
  arg = unwrap(arg);
  if (arg.type === 'CallExpression') {
    // `r.bind(null)` and `r.bind(null).bind(null)`.
    const bound = unwrap(arg.callee);
    if (bound.type !== 'MemberExpression' || !keyIs(bound, /^bind$/)) return [];
    const inner = unwrap(bound.object);
    return inner.type === 'Identifier' ? [inner.name] : inner.type === 'CallExpression' ? wrapperNames(inner) : [];
  }
  if (!FN.test(arg.type)) return [];
  const out = [];
  for (const n of [arg.body, ...descendants(arg.body)]) {
    if (n.type !== 'CallExpression') continue;
    // `r()`, `r.call(null)` and `r.apply(null, [])` all run r.
    const callee = unwrap(n.callee);
    const target = callee.type === 'MemberExpression' && keyIs(callee, /^(call|apply)$/) ? unwrap(callee.object) : callee;
    if (target.type === 'Identifier') out.push(target.name);
  }
  return out;
}

// What a timer will run: `setTimeout(cb, ms)`, but `.call(host, cb, ms)` and `.apply(host, [cb, ms])` shift it.
function callbackOf(timer) {
  const callee = unwrap(timer.callee);
  if (callee.type !== 'MemberExpression' || !isBorrowed(callee)) return timer.arguments[0];
  if (keyIs(callee, /^call$/)) return timer.arguments[1];
  if (!keyIs(callee, /^apply$/)) return timer.arguments[0];
  const list = timer.arguments[1] && unwrap(timer.arguments[1]);
  return list?.type === 'ArrayExpression' ? list.elements[0] : undefined;
}

// A timer whose callback calls the executor's reject is a deadline guard, not a
// sleep. Matching the executor's own second parameter (and what it is copied to) keeps a
// renamed `rej` and a block body legal, which a fixed callee-name selector could not. A
// callback that also touches the first parameter (resolve) can settle the promise on time,
// so it is a sleep with a reject on the side and stays banned.
// A parameter's name, through a default (`res = undefined`). Undefined for a pattern or rest.
const paramName = (p) => (p?.type === 'AssignmentPattern' ? p.left : p)?.name;

// resolveNames is null when the first parameter is a pattern or rest: its uses cannot be seen, so no guard.
// `ee.off('x', resolve)` takes the resolve out of a listener list; it does not call it.
const DETACH = /^(off|removeListener|removeEventListener)$/;
const detaches = (n) => {
  const call = n.parent;
  return call.type === 'CallExpression' && call.arguments.includes(n) && unwrap(call.callee).type === 'MemberExpression' && keyIs(unwrap(call.callee), DETACH);
};

function rejects(context, timerCall, resolveNames, rejectNames) {
  const callback = callbackOf(timerCall) && unwrap(callbackOf(timerCall));
  if (!resolveNames || !rejectNames || !callback) return false;
  // setTimeout(reject, 50) and setTimeout(reject.bind(null, err), 50) hand the reject over by reference.
  if (isIn(callback, rejectNames)) return true;
  if (callback.type === 'CallExpression') {
    const bound = unwrap(callback.callee);
    return bound.type === 'MemberExpression' && keyIs(bound, /^bind$/) && isIn(bound.object, rejectNames);
  }
  // A callback declared in this file (`const late = () => rej(err)`) is judged by its body, like an inline one.
  const fn = callback.type === 'Identifier' ? localFunction(context, callback) : callback;
  if (!fn || !FN.test(fn.type)) return false;
  if (Array.from(resolveNames).some((name) => reaches(context, fn, 'm', name))) return false;
  // Called, or handed to a helper that fails with it.
  return Array.from(rejectNames).some((name) => reaches(context, fn, 'c', name));
}

// The variable a name means, looked up through the scopes around it. A scope that does not hold the name remembers what its parent said, so a
// name read at every level of N nested functions (`Promise` in each executor) costs one step a level, not N.
const scopeNames = new WeakMap();
function variableOf(context, ident) {
  const walked = [];
  let found = null;
  for (let scope = context.sourceCode.getScope(ident); scope; scope = scope.upper) {
    tick();
    const known = scopeNames.get(scope);
    if (known?.has(ident.name)) {
      found = known.get(ident.name);
      break;
    }
    const variable = scope.set.get(ident.name);
    if (variable) {
      found = variable;
      break;
    }
    walked.push(scope);
  }
  for (const scope of walked) {
    if (!scopeNames.has(scope)) scopeNames.set(scope, new Map());
    scopeNames.get(scope).set(ident.name, found);
  }
  return found;
}

// `new Promise(waitFn)` passes a named executor: follow the name to a function
// declared in the file and judge its body like an inline executor. null means it
// is imported, a parameter, or otherwise out of sight.
function localFunction(context, ident) {
  // An overloaded function lists its signatures (TSDeclareFunction) before the body.
  const defs = variableOf(context, ident)?.defs ?? [];
  const def = defs.find((d) => d.node.type === 'FunctionDeclaration') ?? defs[0];
  // A parameter's def.node is the function that declares it, not what it was handed.
  if (!def || def.type === 'Parameter') return null;
  if (def.node.type === 'FunctionDeclaration') return def.node;
  // `const f = () => ...`, also behind a cast: `const f = (() => ...) as () => number`.
  const init = def.node.type === 'VariableDeclarator' && def.node.init ? unwrap(def.node.init) : null;
  return init && FN.test(init.type) ? init : null;
}

// What a callback can run is its own body plus, transitively, the bodies of the functions declared in this file that it mentions
// (`() => late(rej)` runs `late`) and of the functions declared inside it. Without that a helper could settle the promise out of
// sight. Each function is read once into a summary (the names it mentions, the names it calls or passes on, the functions it reaches
// by name or by containing them), and a question about "everything this reaches" is answered from a per-question set built once by
// walking the call edges backward from the functions that hold the answer themselves. N timers that call the same N-line helper
// read it once, not N times.
const unitMemo = new WeakMap();
function unitsOf(context) {
  let units = unitMemo.get(context.sourceCode);
  if (!units) unitMemo.set(context.sourceCode, (units = { own: new Map(), all: null, callers: null, byName: null, sets: new Map() }));
  return units;
}

function ownOf(context, root) {
  const units = unitsOf(context);
  if (units.own.has(root)) return units.own.get(root);
  const own = { mentions: new Set(), calls: new Set(), nodes: [], edges: new Set() };
  units.own.set(root, own);
  for (const stack = FN.test(root.type) ? kidsOf(root) : [root]; stack.length; ) {
    const node = stack.pop();
    if (FN.test(node.type)) {
      own.edges.add(node);
      continue;
    }
    if (node.type === 'Identifier' && isName(node)) {
      if (!detaches(node)) own.mentions.add(node.name);
      const fn = localFunction(context, node);
      if (fn) own.edges.add(fn);
      own.nodes.push(node);
    } else if (node.type === 'MemberExpression') own.nodes.push(node);
    else if (node.type === 'CallExpression') {
      for (const part of [node.callee, ...node.arguments]) if (unwrap(part).type === 'Identifier') own.calls.add(unwrap(part).name);
    }
    for (const kid of kidsOf(node)) stack.push(kid);
  }
  return own;
}

// Every function in the file, who reaches it, and which of them mention or call each name.
function indexUnits(context) {
  const units = unitsOf(context);
  if (units.all) return units;
  units.all = [];
  for (const stack = [context.sourceCode.ast]; stack.length; ) {
    const node = stack.pop();
    if (FN.test(node.type)) units.all.push(node);
    for (const kid of kidsOf(node)) stack.push(kid);
  }
  units.callers = new Map();
  units.byName = { m: new Map(), c: new Map() };
  for (const fn of units.all) {
    const own = ownOf(context, fn);
    for (const e of own.edges) {
      tick();
      if (!units.callers.has(e)) units.callers.set(e, []);
      units.callers.get(e).push(fn);
    }
    for (const [kind, names] of [['m', own.mentions], ['c', own.calls]]) {
      for (const name of names) {
        tick();
        if (!units.byName[kind].has(name)) units.byName[kind].set(name, []);
        units.byName[kind].get(name).push(fn);
      }
    }
  }
  return units;
}

// Does anything `root` reaches hold the answer? kind 'm'/'c' ask for a name mentioned or called; any other kind takes `test`,
// a question about a function's own nodes, and its answer is only valid once the facts it reads have settled.
function reaches(context, root, kind, name, test) {
  const own = ownOf(context, root);
  if (kind === 'm' ? own.mentions.has(name) : kind === 'c' ? own.calls.has(name) : test(own)) return true;
  const units = indexUnits(context);
  const key = `${kind}:${name ?? ''}`;
  let set = units.sets.get(key);
  if (!set) {
    set = new Set(kind === 'm' || kind === 'c' ? (units.byName[kind].get(name) ?? []) : units.all.filter((fn) => test(ownOf(context, fn))));
    for (const fn of set) {
      tick();
      for (const caller of units.callers.get(fn) ?? []) {
        tick();
        set.add(caller);
      }
    }
    units.sets.set(key, set);
  }
  for (const e of own.edges) {
    tick();
    if (set.has(e)) return true;
  }
  return false;
}

// Known gaps (an AST rule, not a dataflow engine). A sleep still gets through when:
// - a resolve reaches a timer through an imported helper (`import { waitFn } from './helpers'; new Promise((r) => waitFn(r))`),
//   or a timer is built in another module;
// - a script, module or timer name is assembled at runtime (`'set' + 'Timeout'`) or computed by a call (`const k = pick()`);
// - a script reaches evaluate through a function's argument (`async function run(s) { await page.evaluate(s); } run('setTimeout(...)')`);
// - the host is handed to a function as an argument (`function f(g) { return new Promise((r) => g.setTimeout(r, 50)); } f(globalThis)`);
// - a module is loaded some other way (`createRequire(import.meta.url)('timers')`, `module.require('timers')`);
// - a `Promise.withResolvers()` bag is returned from a local function (`const mk = () => Promise.withResolvers(); const d = mk()`);
// - a resolve reaches a timer through an object-literal method (`const h = { after: (f) => setTimeout(f, 50) }; new Promise((r) => h.after(r))`),
//   inside an object handed to a helper (`after({ f: r })`), or through `for (const f of [d.resolve]) setTimeout(f, 50)`;
// - a loop spins on a counter and never reads a clock (`for (let i = 0; i < 1e9; i++) {}`), or reads it through a function imported
//   from another module (`import { now } from './clock'; while (now() < end) {}`);
// - the host is reached through itself (`globalThis.globalThis.setTimeout`, `window.self.setTimeout`);
// - the clock is read by `Date.now.call(Date)` or `Reflect.apply(Date.now, Date, [])`, held in an object (`const c = { now: Date.now }; c.now()`),
//   or a local clock function is copied or picked by another name (`const g = f`, `const g = opts.g ?? f`);
// - a resolve is wrapped and stored under another name before it is handed to a helper (`const g = () => r(); after(g)`, `const g = r.bind(null); after(g)`);
// - a timer is started without `setTimeout` or `setInterval` (`AbortSignal.timeout(50)`), or the loop turn is used as a flush (`setImmediate(r)`);
// - the timer is read off the host by a call or a spread (`Reflect.get(globalThis, 'setTimeout')`, `{ ...globalThis }`);
// - a resolve is picked out of an array before it is handed to a timing helper (`after([r][0])`) or passed on by a wrapper to another call (`after(() => Promise.resolve().then(r))`);
// - a bag held by a class or object is copied before its resolve is read (`class Q { static d = Promise.withResolvers(); } const Z = Q; setTimeout(Z.d.resolve, 5)`, `const { d } = Q`, `new Q().d`);
// - a Promise subclass comes from another module (`import { Base } from './base'; new (class extends Base {})((r) => setTimeout(r, 5))`).
// False positives the rule accepts, reported rather than missed: any variable or function named `sleep`
// (`const sleep = 50`); a deadline guard whose timer callback redeclares the resolve name
// (`(r, rej) => setTimeout(() => { const r = 1; rej(e); })`), since names are matched, not scopes; a deadline guard that calls the
// reject through an object literal that holds it (`const o = { rej }; setTimeout(() => o.rej(e), 50)`); and a counted loop with a clock
// guard that breaks (`for (let i = 0; i < 10; i++) { if (Date.now() > end) break; }`), which cannot spin; a local object named `scheduler` or
// `Atomics` with a `wait` method (`const scheduler = { wait }; scheduler.wait(50)`), since globals are matched by name; `new Promise(queueMicrotask)`,
// `new Promise(process.nextTick)` and `new Promise(setImmediate)`, which hand a scheduler to the executor and are reported as unreadable; a
// poll loop that sleeps between checks under one deadline (`while (!ok && Date.now() - start < 1000) { ok = await check(); await new Promise((r) => setTimeout(r, 50)); }`);
// and a timer a fake clock advances at once (`setTimeout(r, 1000); vi.advanceTimersByTime(1000)` in the executor). Leaked resolves are tracked by scope
// variable plus the member path of the place they were stored (casts, parens and `?.` do not change it).
// tests/lint/no-sleep-cases.ts plants one case per spec table row, per gap above and per accepted false positive. A shape outside those lists is untested.
const noSleepPromise = {
  meta: {
    type: 'problem',
    schema: [],
    messages: {
      sleep: `Sleep promise in a test. ${SIGNALS}`,
      opaque: `Promise executor the lint cannot read. Declare it in this file or inline it. ${SIGNALS}`,
    },
  },
  create(context) {
    current = context;
    // `Promise`, `globalThis.Promise`, or a name that is one: `const P = Promise`, `let P; P = Promise`, a default
    // (`(P = Promise) => ...`), `a ?? Promise`, `const { Promise: P } = globalThis` (also by assignment or in a parameter),
    // `class P extends Promise {}`.
    // Answered once per name, like isHost: a failed query has read every write of every name it visited. Without it a `new` on each of N
    // copies of Promise walks the chain from its end each time.
    const promiseMemo = new WeakMap();
    const isPromise = (node) => {
      const seen = new Set();
      const found = promiseIn(node, seen);
      if (!found) for (const variable of seen) promiseMemo.set(variable, false);
      return found;
    };
    const promiseIn = (node, seen) =>
      reach(node, {
        seen,
        memo: promiseMemo,
        // `class P extends Promise {}` as an expression, and as a declaration below.
        leaf: (n) => isHostRef(n, ['Promise']) || (n.type === 'ClassExpression' ? (n.superClass ?? false) : undefined),
        more: (variable) => variable.defs.filter((def) => def.node.type === 'ClassDeclaration' && def.node.superClass).map((def) => def.node.superClass),
      });
    // scope variable -> paths of the places a resolve was copied into. Keyed by variable so
    // an unrelated `r()` in another scope is not mistaken for the leaked one.
    const leaked = new Map();
    // The places a resolve was stored where code can call it back (`rs.push(res)`, `x = res`). `leaked` also holds the places
    // that only listen for it (`child.on('exit', res)`): a deadline guard may touch those (`child.kill()`).
    const held = new Map();
    const LISTEN = /^(on|once|addListener|prependListener|prependOnceListener|addEventListener)$/;
    const listens = (callee) => callee.type === 'MemberExpression' && keyIs(callee, LISTEN);
    // A `this.x` is rooted at its own class, so two classes with a field of the same name do not share a place.
    const rootVariable = (node) => {
      let root = unwrap(node);
      while (root.type === 'MemberExpression') root = unwrap(root.object);
      if (root.type === 'ThisExpression') {
        const inside = classOf(root);
        const name = inside?.isStatic ? staticName(inside.klass) : null;
        return name ? variableOf(context, { type: 'Identifier', name, parent: inside.klass.parent }) : (inside?.klass ?? null);
      }
      if (root.type !== 'Identifier') return null;
      // Inside its own body a class name is the class-scope binding, and outside it is the declaration's; both are the one class, so
      // `Q.r = ...` in a static block and `Q.r` after the class share a place.
      const variable = variableOf(context, root);
      const klass = variable?.scope.type === 'class' ? variable.defs[0]?.node : null;
      return klass?.type === 'ClassDeclaration' ? (variableOf(context, { type: 'Identifier', name: root.name, parent: klass.parent }) ?? variable) : variable;
    };
    // The flow pass is a worklist: an item (a flow or a call) is re-run only when a place it read gains a path, so a
    // long chain of copies costs one visit per link, not a full sweep per link.
    const watchers = new Map();
    const queue = [];
    const queued = new Set();
    let running = null;
    const watchSet = (map, variable, path) => {
      if (!watchers.has(map)) watchers.set(map, new Map());
      const byVariable = watchers.get(map);
      if (!byVariable.has(variable)) byVariable.set(variable, new Map());
      const byPath = byVariable.get(variable);
      if (!byPath.has(path)) byPath.set(path, new Set());
      return byPath.get(path);
    };
    const addPath = (map, target, path) => {
      const variable = rootVariable(target);
      if (!map.has(variable)) map.set(variable, new Set());
      const places = map.get(variable);
      if (places.has(path)) return;
      places.add(path);
      for (const item of watchers.get(map)?.get(variable)?.get(path) ?? []) {
        if (!queued.has(item)) {
          queued.add(item);
          queue.push(item);
        }
      }
    };
    const has = (map, node) => {
      const variable = rootVariable(node);
      const path = pathOf(node);
      if (running && path !== null) watchSet(map, variable, path).add(running);
      return !!map.get(variable)?.has(path);
    };
    const leak = (target, path = pathOf(target), weak = false) => {
      if (path === null) return;
      addPath(leaked, target, path);
      if (!weak) addPath(held, target, path);
      // `rs[0] = res` can be read back through any index or by draining the array.
      const slot = unwrap(target);
      if (slot.type === 'MemberExpression' && slot.computed) leak(slot.object);
    };
    // Where a resolve ends up: `x = res`, `xs.push(res)`, or `stash(res)` for a helper declared in
    // this file that does either with its parameter. A helper that hands it to a timer
    // (`const after = (f) => setTimeout(f, 50)`) is a sleep: its timers go in hits.
    // One hop per helper; anything else is a gap. Returns every name the resolve goes by in fn.
    // What a helper does with a parameter does not depend on who calls it, so each (helper, parameter) is
    // walked once; `cuts` counts the times a recursion was cut short, and a cut walk is not remembered
    // (it stopped at a function still being walked, so it may have missed that function's timers).
    const followed = new Map();
    const ids = new WeakMap();
    let cuts = 0;
    let nextId = 0;
    const idOf = (fn) => {
      if (!ids.has(fn)) ids.set(fn, nextId++);
      return ids.get(fn);
    };
    // Helpers that call helpers are walked with a stack of frames, not by recursion: a chain of N helpers is N levels.
    const follow = (fn, name, hits, seen = new Set(), inHelper = false) => {
      const frames = [];
      const open = (fn, name, into, inHelper) => {
        tick();
        if (!name) return new Set();
        const key = `${inHelper}:${name}`;
        const known = followed.get(fn)?.get(key);
        if (known) {
          for (const h of known.hits) into.add(h);
          return known.names;
        }
        // Keyed by the parameter too: `after(r, 0); after(0, r)` walks `after` once per parameter.
        const visit = `${idOf(fn)}:${name}`;
        if (seen.has(visit)) {
          cuts++;
          return new Set();
        }
        seen.add(visit);
        const own = new Set();
        const { names, todo } = walk(fn, name, own, inHelper);
        frames.push({ fn, key, into, own, names, todo, next: 0, before: cuts });
        return names;
      };
      const names = open(fn, name, hits, inHelper);
      while (frames.length) {
        const top = frames.at(-1);
        tick();
        if (top.next < top.todo.length) {
          const [helper, param] = top.todo[top.next++];
          open(helper, param, top.own, true);
          continue;
        }
        frames.pop();
        if (cuts === top.before) followed.set(top.fn, (followed.get(top.fn) ?? new Map()).set(top.key, { names: top.names, hits: top.own }));
        for (const h of top.own) top.into.add(h);
      }
      return names;
    };
    // The places a question can be about, found once and looked up by name inside a function's range, so a function nested N deep
    // is not re-read from the top by every level above it. Each list is in source order.
    let found = null;
    const byStart = (x, y) => x.range[0] - y.range[0];
    const index = () => {
      if (found) return found;
      found = { copies: new Map(), assigns: new Map(), calls: new Map(), wrapped: new Map(), timerArgs: new Map(), timers: [...timers].sort(byStart) };
      const put = (map, name, node) => {
        if (!map.has(name)) map.set(name, []);
        map.get(name).push(node);
      };
      const held = (value, out) => {
        value = unwrap(value);
        if (value.type === 'LogicalExpression') [value.left, value.right].forEach((v) => held(v, out));
        else if (value.type === 'ConditionalExpression') [value.consequent, value.alternate].forEach((v) => held(v, out));
        else if (value.type === 'ArrayExpression') value.elements.forEach((e) => e && held(e, out));
        else if (value.type === 'ObjectExpression') value.properties.forEach((p) => p.type === 'Property' && held(p.value, out));
        else if (value.type === 'Identifier') out.add(value.name);
      };
      for (const [target, value] of flows) {
        tick();
        const node = target.parent;
        if (!node || !value) continue;
        if (node.type === 'AssignmentExpression' && unwrap(value).type === 'Identifier') put(found.assigns, unwrap(value).name, node);
        if (target.type !== 'Identifier' || (node.type !== 'VariableDeclarator' && node.type !== 'AssignmentExpression')) continue;
        const names = new Set();
        held(value, names);
        for (const name of names) put(found.copies, name, node);
      }
      for (const call of calls) {
        tick();
        for (const name of new Set(call.arguments.map((a) => unwrap(a)).filter((a) => a.type === 'Identifier').map((a) => a.name))) put(found.calls, name, call);
        for (const name of new Set(call.arguments.flatMap(wrapperNames))) put(found.wrapped, name, call);
      }
      for (const timer of timers) {
        tick();
        const names = new Set();
        for (const arg of timer.arguments) for (const x of [arg, ...descendants(arg)]) if (x.type === 'Identifier' && isName(x)) names.add(x.name);
        for (const name of names) put(found.timerArgs, name, timer);
      }
      for (const list of [found.copies, found.assigns, found.calls, found.wrapped, found.timerArgs]) for (const nodes of list.values()) nodes.sort(byStart);
      return found;
    };
    // Where the nodes of a start-ordered list that begin at or after `root` do.
    const startAt = (list, root) => {
      let lo = 0;
      for (let hi = list.length; lo < hi; ) {
        tick();
        const mid = (lo + hi) >> 1;
        if (list[mid].range[0] < root.range[0]) lo = mid + 1;
        else hi = mid;
      }
      return lo;
    };
    // The nodes of a start-ordered list that lie inside `root`.
    const within = (list, root) => {
      if (!list) return [];
      const lo = startAt(list, root);
      const out = [];
      for (let i = lo; i < list.length && list[i].range[0] < root.range[1]; i++) {
        tick();
        if (list[i].range[1] <= root.range[1]) out.push(list[i]);
      }
      return out;
    };
    // A name plus every name it is copied to (`const done = res`, `let d; d = res`, `const o = { res }`), by name inside `root`.
    const aliasesIn = (root, name) => {
      const names = new Set([name]);
      for (const queue = [name]; queue.length; ) {
        tick();
        for (const n of within(index().copies.get(queue.pop()), root)) {
          const [id, value] = n.type === 'VariableDeclarator' ? [n.id, n.init] : [n.left, n.right];
          if (names.has(id.name) || !holds(value, names)) continue;
          names.add(id.name);
          queue.push(id.name);
        }
      }
      return names;
    };
    // What one function does with a name: its leaks and timers now, and the helpers it hands the name to, for follow to walk next.
    const walk = (fn, name, hits, inHelper) => {
      const root = fn.body;
      const names = aliasesIn(root, name);
      const named = (a) => isIn(a, names);
      const at = new Map();
      for (const x of names) {
        for (const n of within(index().assigns.get(x), root)) leak(n.left);
        for (const n of within(index().calls.get(x), root)) at.set(n, n.arguments.findIndex(named));
        if (inHelper) for (const n of within(index().timerArgs.get(x), root)) hits.add(n);
      }
      // `after(r.bind(null))` and `after(() => r())` hand the helper something that settles the promise; the helper may time it.
      const wrapped = new Map();
      for (const x of names) {
        for (const n of within(index().wrapped.get(x), root)) if (!at.has(n)) wrapped.set(n, n.arguments.findIndex((a) => wrapperNames(a).some((v) => names.has(v))));
      }
      const todo = [];
      for (const [n, i] of [...at, ...wrapped].sort(([x], [y]) => byStart(x, y))) {
        const callee = unwrap(n.callee);
        if (callee.type === 'MemberExpression' && !keyIs(callee, DETACH) && at.has(n)) leak(callee.object, undefined, listens(callee));
        if (callee.type === 'Identifier') {
          const helper = localFunction(context, callee);
          if (helper) todo.push([helper, paramName(paramsOf(helper)[i])]);
        }
      }
      return { names, todo };
    };
    // `Promise.withResolvers()` hands out a bag whose `.resolve` can go anywhere. The flow pass
    // below follows the bag and the resolve through declarations, assignments, array and object
    // literals, destructuring and calls, until nothing new is reached.
    const bags = new Map();
    const flows = [];
    const calls = [];
    // `Promise.withResolvers` itself, bound (`.bind(Promise)`), held in a name (any write counts), or destructured off Promise.
    const makesBag = (fn) =>
      reach(fn, {
        seen: new Set(),
        leaf(n) {
          if (n.type === 'MemberExpression') return keyIs(n, /^withResolvers$/) && isPromise(n.object);
          if (n.type === 'CallExpression') {
            const callee = unwrap(n.callee);
            return callee.type === 'MemberExpression' && keyIs(callee, /^bind$/) ? callee.object : false;
          }
          return n.type === 'Identifier' ? undefined : false;
        },
        direct: (variable) =>
          variable.references.some((ref) => {
            const bound = ref.isWrite() ? boundBy(ref.identifier) : null;
            const source = bound && sourceOf(bound.pattern);
            return !!source && propKeys(bound.prop).includes('withResolvers') && isPromise(source);
          }),
      });
    const isBag = (value) => {
      value = unwrap(value);
      if (value.type === 'CallExpression') {
        const callee = unwrap(value.callee);
        // `Promise.withResolvers.call(Promise)` and `.apply(Promise, [])`.
        if (callee.type === 'MemberExpression' && keyIs(callee, /^(call|apply)$/) && makesBag(callee.object)) return true;
        return makesBag(callee);
      }
      return (value.type === 'Identifier' || value.type === 'MemberExpression') && has(bags, value);
    };
    // The value is a leaked resolve, or an array/object literal holding one.
    const carries = (value) => {
      value = unwrap(value);
      if (value.type === 'LogicalExpression') return carries(value.left) || carries(value.right);
      if (value.type === 'ConditionalExpression') return carries(value.consequent) || carries(value.alternate);
      if (value.type === 'ArrayExpression') return value.elements.some((e) => e && carries(e));
      if (value.type === 'ObjectExpression') return value.properties.some((p) => p.type === 'Property' && carries(p.value));
      if (value.type === 'CallExpression') {
        const callee = unwrap(value.callee);
        return callee.type === 'MemberExpression' && keyIs(callee, /^bind$/) && carries(callee.object);
      }
      return (value.type === 'Identifier' || value.type === 'MemberExpression') && has(leaked, value);
    };
    const leaves = (pattern) => {
      if (pattern.type === 'Identifier') return [pattern];
      if (pattern.type === 'AssignmentPattern') return leaves(pattern.left);
      if (pattern.type === 'RestElement') return leaves(pattern.argument);
      if (pattern.type === 'ArrayPattern') return pattern.elements.flatMap((e) => (e ? leaves(e) : []));
      if (pattern.type === 'ObjectPattern') return pattern.properties.flatMap((p) => leaves(p.type === 'Property' ? p.value : p));
      return [];
    };
    // `const e = { d }` and `const q = [d]` with d a bag: e.d and q.0 are bags, so `e.d.resolve` is a leaked resolve.
    const store = (target, value, path) => {
      value = unwrap(value);
      const items =
        value.type === 'ArrayExpression'
          ? value.elements.map((item, i) => [String(i), item])
          : value.type === 'ObjectExpression'
            ? value.properties.map((p) => [p.type === 'Property' ? propKey(p) : undefined, p.value])
            : [];
      for (const [key, item] of items) {
        if (!item || key === undefined) continue;
        if (isBag(item)) {
          addPath(bags, target, `${path}.${key}`);
          leak(target, `${path}.${key}.resolve`);
        } else store(target, item, `${path}.${key}`);
      }
    };
    const flow = (target, value) => {
      const path = target.type === 'Identifier' || target.type === 'MemberExpression' ? pathOf(target) : null;
      if (path !== null) store(target, value, path);
      if (isBag(value)) {
        if (target.type !== 'ObjectPattern') {
          const path = pathOf(target);
          if (path === null) return;
          addPath(bags, target, path);
          return leak(target, `${path}.resolve`);
        }
        for (const prop of target.properties) {
          if (prop.type === 'Property' && propKeys(prop).includes('resolve')) leaves(prop.value).forEach((id) => leak(id));
        }
      } else if (carries(value)) {
        if (target.type === 'Identifier' || target.type === 'MemberExpression') leak(target);
        else leaves(target).forEach((id) => leak(id));
      }
    };
    // `q.push(d.resolve)` parks it in q, `stash(d.resolve)` in whatever the helper does with it.
    const pass = (call, hits) => {
      const at = call.arguments.findIndex(carries);
      if (at < 0) return;
      const callee = unwrap(call.callee);
      if (callee.type === 'MemberExpression' && !keyIs(callee, DETACH)) leak(callee.object, undefined, listens(callee));
      const helper = callee.type === 'Identifier' ? localFunction(context, callee) : null;
      if (helper) follow(helper, paramName(paramsOf(helper)[at]), hits, new Set(), true);
    };
    const timers = [];
    // executor function -> the names its resolve and reject go by, so a timer inside it can be told from a deadline guard.
    const executors = new WeakMap();
    const reported = new Set();
    const report = (node, messageId) => {
      if (reported.has(node)) return;
      reported.add(node);
      context.report({ node, messageId });
    };
    let skip = null;
    // Judge the executor `arg` handed to a Promise built at `node`.
    const judge = (node, arg) => {
      let executor = arg;
      if (executor.type === 'Identifier') {
        const named = localFunction(context, executor);
        // An executor from another module cannot be judged, so it cannot be trusted.
        if (!named) return report(node, 'opaque');
        executor = named;
      }
      // `obj.fn`, `makeWait(50)`, `...args`: there is no function here to read.
      if (!FN.test(executor.type)) return report(node, 'opaque');
      const resolveName = paramName(paramsOf(executor)[0]);
      const rejectName = paramName(paramsOf(executor)[1]);
      const hits = new Set();
      const followed = follow(executor, resolveName, hits);
      if (hits.size) report(node, 'sleep');
      const resolveNames = paramsOf(executor)[0] && !resolveName ? null : followed;
      const rejectNames = rejectName ? aliasesIn(executor.body, rejectName) : null;
      executors.set(executor, { resolveNames, rejectNames });
      // A timer this loop has already reported is not read again by the executors around it, so executors nested N deep that each hold a
      // deadline guard cost N, not N^2 / 2: `skip[i]` is the first timer at or after i that is still to be judged.
      const all = index().timers;
      skip ??= Array.from({ length: all.length + 1 }, (_, i) => i);
      const live = (i) => {
        let j = i;
        while (skip[j] !== j) j = skip[j];
        for (let k = i; k !== j; ) {
          const next = skip[k];
          skip[k] = j;
          k = next;
        }
        return j;
      };
      for (let i = live(startAt(all, executor.body)); i < all.length && all[i].range[0] < executor.body.range[1]; i = live(i + 1)) {
        tick();
        const n = all[i];
        if (n.range[1] > executor.body.range[1] || rejects(context, n, resolveNames, rejectNames)) continue;
        if (arg !== executor) {
          report(node, 'sleep');
          break;
        }
        report(n, 'sleep');
        skip[i] = i + 1;
      }
    };
    // Promises are judged at the end, once every timer, call and copy in the file has been seen.
    const judged = [];
    return {
      CallExpression(node) {
        if (isTimer(node.callee)) timers.push(node);
        calls.push(node);
        // `Reflect.construct(Promise, [executor])` builds the same promise as `new Promise(executor)`.
        const callee = unwrap(node.callee);
        if (callee.type !== 'MemberExpression' || !keyIs(callee, /^construct$/) || !isHostRef(callee.object, ['Reflect'])) return;
        if (!node.arguments[0] || !isPromise(node.arguments[0]) || !node.arguments[1]) return;
        const list = unwrap(node.arguments[1]);
        if (list.type !== 'ArrayExpression') return report(node, 'opaque');
        const first = list.elements[0];
        if (first) judged.push([node, unwrap(first)]);
      },
      NewExpression(node) {
        // `new (Promise as never)(...)` and `new globalThis.Promise(...)` are still the real Promise.
        if (!isPromise(node.callee)) return;
        if (node.arguments[0]) judged.push([node, unwrap(node.arguments[0])]);
      },
      VariableDeclarator(node) {
        if (node.init) flows.push([node.id, node.init]);
      },
      AssignmentExpression(node) {
        flows.push([node.left, node.right]);
      },
      // `class A { d = Promise.withResolvers() }` is read back as `this.d`, or `A.d` when static. The name is looked up from
      // outside the class, where a later `A.d` resolves it; a class with no name is only reachable through `this`.
      PropertyDefinition(node) {
        if (!node.value || node.computed) return;
        const klass = node.parent.parent;
        const name = node.static ? staticName(klass) : null;
        // Inside the class the name is its own binding, so a bag reached as `A.d` in a method needs the flow looked up from the field too.
        const owners = name ? [{ type: 'Identifier', name, parent: klass.parent }, { type: 'Identifier', name, parent: node }] : [{ type: 'ThisExpression', parent: node }];
        for (const object of owners) flows.push([{ type: 'MemberExpression', object, property: node.key, computed: false }, node.value]);
      },
      'Program:exit'() {
        const hits = new Set();
        for (const [node, arg] of judged) judge(node, arg);
        for (const [target, value] of flows) queue.push(() => flow(target, value));
        for (const call of calls) queue.push(() => pass(call, hits));
        for (const item of queue) queued.add(item);
        for (let head = 0; head < queue.length; head++) {
          running = queue[head];
          tick();
          queued.delete(running);
          running();
        }
        running = null;
        for (const call of hits) report(call, 'sleep');
        if (!leaked.size) return;
        // A timer inside the executor whose callback calls that executor's reject is a deadline guard. Touching a place that
        // only listens for the resolve (`child.kill()` after `child.on('exit', r)`) does not make it a sleep; touching one that
        // stores the resolve, or emitting on the listener, does.
        const guards = (timer) => {
          for (let up = timer.parent; up; up = up.parent) {
            const info = executors.get(up);
            if (info) return rejects(context, timer, info.resolveNames, info.rejectNames);
          }
          return false;
        };
        const emits = (n) => n.parent.type === 'MemberExpression' && n.parent.object === n && keyIs(n.parent, /^emit$/);
        const touchesLeaked = (own) => own.nodes.some((n) => has(leaked, n));
        const touchesHeld = (own) => own.nodes.some((n) => has(leaked, n) && (has(held, n) || emits(n)));
        for (const timer of timers) {
          tick();
          // `setTimeout(f, 50)` with `const f = () => r()` runs what f's body does, and so does a function f calls.
          if (!timer.arguments.some((arg) => reaches(context, arg, 't', '', touchesLeaked))) continue;
          if (guards(timer) && !timer.arguments.some((arg) => reaches(context, arg, 'h', '', touchesHeld))) continue;
          report(timer, 'sleep');
        }
      },
    };
  },
};

// Saving the real timer to put it back (`const orig = setTimeout; ...; setTimeout = orig`)
// is stub housekeeping. Calling or passing the saved copy on is the alias.
const noTimerAlias = {
  meta: {
    type: 'problem',
    schema: [],
    messages: {
      alias: `Aliasing setTimeout hides a sleep. Saving it to restore later is fine, calling or passing the copy is not. ${SIGNALS}`,
      destructure: `Destructuring a timer off a global host hides a sleep. ${SIGNALS}`,
      passed: `setTimeout passed as a value is a sleep in disguise. ${SIGNALS}`,
      promisify: `promisify(setTimeout) is a sleep. ${SIGNALS}`,
    },
  },
  create(context) {
    current = context;
    // The real timer handed over as an argument: `run(globalThis.setTimeout)`, `run(g.setTimeout)` with `g = globalThis`, behind a
    // cast. Asserting on it (`expect(globalThis.setTimeout)`) schedules nothing; promisifying it is a sleep wherever it sits.
    // `expect(x)`, `expect(x).toBe(...)`, `expect(x).not.toBe(...)`, `expect.soft(x).toBe(...)`, `assert.strictEqual(...)`, `vi.mocked(x)`.
    const inspecting = (callee) => {
      let root = unwrap(callee);
      if (root.type === 'MemberExpression' && root.object.name === 'vi') return /^(isMockFunction|mocked)$/.test(root.property.name ?? '');
      while (root.type === 'MemberExpression' || root.type === 'CallExpression') root = unwrap(root.type === 'MemberExpression' ? root.object : root.callee);
      return root.type === 'Identifier' && /^(expect|assert)/.test(root.name);
    };
    const passes = (node) => {
      const callee = unwrap(node.callee);
      const promisify = (callee.type === 'Identifier' && callee.name === 'promisify') || (callee.type === 'MemberExpression' && callee.property.name === 'promisify');
      const inspects = inspecting(callee);
      if (inspects && !promisify) return;
      for (const arg of node.arguments) {
        const value = unwrap(arg);
        if (value.type === 'MemberExpression' && isTimerRef(value)) context.report({ node: value, messageId: promisify ? 'promisify' : 'passed' });
      }
    };
    // Only the real slot counts: `setTimeout = orig`, `globalThis.setTimeout = orig`, `vi.stubGlobal('setTimeout', orig)`.
    // `h.setTimeout = orig` or `m.set('setTimeout', orig)` parks the timer somewhere a later call can reach.
    const isRestore = (ref) => {
      // `orig as never` and `orig!` put the same function back.
      let id = ref;
      while (/^(TSAsExpression|TSNonNullExpression|TSSatisfiesExpression|TSTypeAssertion)$/.test(id.parent.type)) id = id.parent;
      const p = id.parent;
      // `expect(globalThis.setTimeout).toBe(orig)` reads the copy, it does not call it.
      if (p.type === 'CallExpression' && p.arguments.includes(id) && inspecting(p.callee)) return true;
      if (p.type === 'AssignmentExpression' && p.right === id) return isHostRef(p.left, TIMER_NAMES);
      if (p.type !== 'CallExpression' || !TIMER_NAMES.includes(p.arguments[0]?.value) || p.arguments[1] !== id) return false;
      return p.callee.type === 'MemberExpression' && p.callee.object.name === 'vi' && p.callee.property.name === 'stubGlobal';
    };
    const onlyRestored = (variable) =>
      !variable || variable.references.every((ref) => ref.isWrite() || isRestore(ref.identifier));
    const findVariable = (node, name) => {
      for (let scope = context.sourceCode.getScope(node); scope; scope = scope.upper) {
        const variable = scope.set.get(name);
        if (variable) return variable;
      }
      return null;
    };
    return {
      CallExpression: passes,
      NewExpression: passes,
      VariableDeclarator(node) {
        if (!node.init || !isTimerRef(node.init)) return;
        if (node.id.type !== 'Identifier') return context.report({ node, messageId: 'alias' });
        const variable = context.sourceCode.getDeclaredVariables(node).find((v) => v.name === node.id.name);
        if (!onlyRestored(variable)) context.report({ node, messageId: 'alias' });
      },
      // The real timer parked in a value slot is callable from anywhere later.
      Property(node) {
        if (node.parent.type === 'ObjectExpression' && isTimerRef(node.value)) context.report({ node, messageId: 'alias' });
        // `const { setTimeout: wait } = globalThis`, by declaration, assignment or parameter default, behind a cast, with a computed key.
        // Only off a host: `const { setTimeout: ms } = opts` reads a config value.
        if (node.parent.type === 'ObjectPattern' && propKeys(node).some((k) => TIMER_NAMES.includes(k)) && fromHost(node.parent)) {
          context.report({ node, messageId: 'destructure' });
        }
      },
      AssignmentPattern(node) {
        if (isTimerRef(node.right)) context.report({ node, messageId: 'alias' });
      },
      PropertyDefinition(node) {
        if (node.value && isTimerRef(node.value)) context.report({ node, messageId: 'alias' });
      },
      ArrayExpression(node) {
        for (const el of node.elements) if (el && isTimerRef(el)) context.report({ node: el, messageId: 'alias' });
      },
      // Handed back from a function, or held in a template: `return setTimeout`, `() => setTimeout`, `${setTimeout}`.
      ReturnStatement(node) {
        if (node.argument && isTimerRef(node.argument)) context.report({ node, messageId: 'alias' });
      },
      ArrowFunctionExpression(node) {
        if (node.body.type !== 'BlockStatement' && isTimerRef(node.body)) context.report({ node, messageId: 'alias' });
      },
      TemplateLiteral(node) {
        for (const e of node.expressions) if (isTimerRef(e)) context.report({ node: e, messageId: 'alias' });
      },
      AssignmentExpression(node) {
        if (!isTimerRef(node.right) || isHostRef(node.left, TIMER_NAMES)) return;
        if (node.left.type !== 'Identifier') return context.report({ node, messageId: 'alias' });
        if (!onlyRestored(findVariable(node, node.left.name))) context.report({ node, messageId: 'alias' });
      },
    };
  },
};


// A browser driver, the thread-blocking waits, and loops that spin on the clock: sleeps that
// never touch setTimeout in the test body.
// Page drivers hand a script to the page; `eval` and `Function` run one in this process.
const SCRIPT_CALLS = new Set(['evaluate', 'evaluateHandle', 'evaluateOnNewDocument', 'waitForFunction', 'addInitScript', 'addScriptTag', '$eval', '$$eval', 'eval', 'Function']);

// The literal text a call hands a page as a script: a string, a template (holes aside), a const holding
// one, or the same inside an object (`{ content: '...' }`) or array.
function scriptText(node, seen = new Set()) {
  const parts = [];
  for (const stack = [node]; stack.length; ) {
    const n = unwrap(stack.pop());
    if (n.type === 'Literal') parts.push(typeof n.value === 'string' ? n.value : '');
    else if (n.type === 'TemplateLiteral') parts.push(n.quasis.map((q) => q.value.cooked).join(' '));
    else if (n.type === 'Identifier') {
      const variable = current ? variableOf(current, n) : null;
      if (!variable || seen.has(variable)) continue;
      seen.add(variable);
      stack.push(...writes(variable).filter(Boolean).reverse());
    } else if (n.type === 'ArrayExpression') stack.push(...n.elements.filter(Boolean).reverse());
    else if (n.type === 'ObjectExpression') stack.push(...n.properties.filter((p) => p.type === 'Property').map((p) => p.value).reverse());
  }
  return parts.join(' ');
}

// A function handed to the page that sets a timer runs it there: `addInitScript(() => { setTimeout(...) })`,
// also one declared in this file (`page.evaluate(fn)`).
const setsTimer = (arg) => {
  let fn = unwrap(arg);
  if (fn.type === 'Identifier' && current) fn = localFunction(current, fn) ?? fn;
  return FN.test(fn.type) && [fn.body, ...descendants(fn.body)].some((n) => n.type === 'CallExpression' && isTimer(n.callee));
};

// A function declared in this file that returns a clock read and does nothing else (`const elapsed = () => Date.now() - start`,
// `function now() { return performance.now(); }`): calling it reads the clock. One with an await or another call is work.
// The set is solved for the whole file at once, so a chain of N links costs N and a cycle is judged as a group: a ring
// of helpers that call each other is still a clock when one of them reads it, and a ring that reads nothing is not.
const clockSets = new WeakMap();
function isClockFn(fn) {
  if (!current) return false;
  let set = clockSets.get(current.sourceCode);
  if (!set) clockSets.set(current.sourceCode, (set = clockFnSet(current)));
  return set.has(fn);
}
function clockFnSet(context) {
  const units = [];
  for (const stack = [context.sourceCode.ast]; stack.length; ) {
    const node = stack.pop();
    if (FN.test(node.type)) units.push(node);
    for (const kid of kidsOf(node)) stack.push(kid);
  }
  // Per function, without looking inside the functions it declares: a call or await that is work, the local functions it
  // calls, the ones it declares, and what its return statements hold.
  const info = new Map();
  for (const fn of units) {
    const own = { bad: false, calls: new Set(), children: new Set(), reads: false, returns: new Set() };
    info.set(fn, own);
    const scan = (root, returned) => {
      for (const stack = [root]; stack.length; ) {
        const node = stack.pop();
        tick();
        if (FN.test(node.type) && node !== fn) {
          own.children.add(node);
          // Defaults and destructuring in its parameters run when it is called, and a clock read there is no return value.
          for (const kid of node.params) stack.push(kid);
          continue;
        }
        if (node.type === 'AwaitExpression') own.bad = true;
        if (node.type === 'NewExpression' || node.type === 'CallExpression') {
          if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && localFunction(context, node.callee)) own.calls.add(localFunction(context, node.callee));
          else if (!directClockRead(node) && !isWrapper(node)) own.bad = true;
        }
        if (returned) {
          if (directClockRead(node)) own.reads = true;
          if (node.type === 'CallExpression' && node.callee.type === 'Identifier') {
            const target = localFunction(context, node.callee);
            if (target) own.returns.add(target);
          }
        }
        for (const kid of kidsOf(node)) stack.push(kid);
      }
    };
    scan(fn.body, false);
    // Returned expressions are scanned again for what they hold, outside any nested function.
    if (fn.body.type !== 'BlockStatement') scan(fn.body, true);
    else {
      for (const stack = [fn.body]; stack.length; ) {
        const node = stack.pop();
        tick();
        if (FN.test(node.type) && node !== fn) continue;
        if (node.type === 'ReturnStatement' && node.argument) scan(node.argument, true);
        for (const kid of kidsOf(node)) stack.push(kid);
      }
    }
  }
  // A function is a clock when it is pure (no await, and every call is a clock read or a call to another clock) and returns a
  // read. Purity is the largest set closed under "my callees are clocks" and "my inner functions are pure"; the clocks are the
  // smallest set grounded in a direct read. Both start from the whole file and only shrink, and a function that leaves either
  // set is pushed to the ones that depend on it (its callers, its parents, the functions that return it), so a cascade of N
  // links costs N, not N rounds over the file.
  const pure = new Set(units.filter((fn) => !info.get(fn).bad));
  const callers = new Map();
  const parents = new Map();
  const returnedBy = new Map();
  const link = (map, key, fn) => {
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(fn);
  };
  for (const fn of pure) {
    tick();
    const own = info.get(fn);
    for (const t of own.calls) link(callers, t, fn);
    for (const c of own.children) link(parents, c, fn);
    for (const t of own.returns) link(returnedBy, t, fn);
  }
  const clocks = new Set(Array.from(pure).filter((fn) => info.get(fn).reads));
  for (const fn of clocks) {
    tick();
    for (const caller of returnedBy.get(fn) ?? []) clocks.add(caller);
  }
  // How many of the things a function returns are clocks: it stays one while it reads, or while that is above zero.
  const support = new Map();
  for (const fn of pure) support.set(fn, Array.from(info.get(fn).returns).filter((t) => clocks.has(t)).length);
  const leftPure = [];
  const leftClocks = [];
  const drop = (fn) => {
    if (pure.delete(fn)) leftPure.push(fn);
  };
  for (const fn of Array.from(pure)) {
    tick();
    const own = info.get(fn);
    if (!Array.from(own.calls).every((t) => clocks.has(t)) || !Array.from(own.children).every((c) => pure.has(c))) drop(fn);
  }
  while (leftPure.length || leftClocks.length) {
    while (leftPure.length) {
      const fn = leftPure.pop();
      tick();
      if (clocks.has(fn)) leftClocks.push(fn);
      for (const parent of parents.get(fn) ?? []) drop(parent);
    }
    while (leftClocks.length) {
      const fn = leftClocks.pop();
      tick();
      if (!clocks.delete(fn)) continue;
      for (const caller of callers.get(fn) ?? []) drop(caller);
      for (const g of returnedBy.get(fn) ?? []) {
        if (!clocks.has(g)) continue;
        support.set(g, support.get(g) - 1);
        if (!info.get(g).reads && support.get(g) === 0) leftClocks.push(g);
      }
    }
  }
  return clocks;
}

// `Date.now`, `performance.now.bind(performance)`, or a name set to one (`const now = Date.now`, `const { now } = performance`).
const CLOCKS = ['Date', 'performance'];
// Answered once per name, like isHost: a failed query has read every write of every name it visited, and a name that is a copy is one
// whatever the walk skipped. Without it a loop per alias walks the chain from its end each time.
const clockMemo = new WeakMap();
function isClockCopy(node) {
  const seen = new Set();
  const found = clockCopyIn(node, seen);
  if (!found) for (const variable of seen) clockMemo.set(variable, false);
  return found;
}
function clockCopyIn(node, seen) {
  return reach(node, {
    seen,
    memo: clockMemo,
    leaf(n) {
      if (n.type === 'MemberExpression') return keyIs(n, /^now$/) && isHostRef(n.object, CLOCKS);
      if (n.type === 'CallExpression') {
        const callee = unwrap(n.callee);
        return callee.type === 'MemberExpression' && keyIs(callee, /^bind$/) ? callee.object : false;
      }
      return undefined;
    },
    direct: (variable) =>
      variable.references.some((ref) => {
        const bound = ref.isWrite() ? boundBy(ref.identifier) : null;
        const source = bound && sourceOf(bound.pattern);
        return !!source && propKeys(bound.prop).includes('now') && isHostRef(source, CLOCKS);
      }),
  });
}

// `Date.now()`, `performance.now()`, `new Date()` with no argument (`new Date(x)` parses or copies a date), `process.hrtime()`, `process.hrtime.bigint()`, a call to a copy of one of those
// (`const now = Date.now; now()`), or a call to a local function that returns one.
// Not counting a call to a local function, which is a read only when that function is a clock (see clockFnSet).
function directClockRead(n) {
  if (n.type === 'NewExpression') return n.arguments.length === 0 && isHostRef(n.callee, ['Date']);
  if (n.type !== 'CallExpression') return false;
  const callee = unwrap(n.callee);
  if (callee.type !== 'MemberExpression') return /^(Identifier|LogicalExpression|ConditionalExpression)$/.test(callee.type) && isClockCopy(callee);
  if (keyIs(callee, /^now$/) && isHostRef(callee.object, CLOCKS)) return true;
  return keyIs(callee, /^hrtime$/) || (keyIs(callee, /^bigint$/) && callee.object.type === 'MemberExpression' && keyIs(callee.object, /^hrtime$/));
}
// `.getTime()` / `.valueOf()` on a call or `new`: the read inside it is judged on its own.
const isWrapper = (n) => n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && keyIs(n.callee, /^(getTime|valueOf)$/) && /^(CallExpression|NewExpression)$/.test(unwrap(n.callee.object).type);
const isClockRead = (n) => {
  if (n.type === 'CallExpression' && unwrap(n.callee).type === 'Identifier') {
    const fn = current ? localFunction(current, unwrap(n.callee)) : null;
    if (fn) return isClockFn(fn);
  }
  return directClockRead(n);
};
// A clock read, or `.getTime()` / `.valueOf()` on one: reading the time is not doing work.
const isClock = (n) =>
  isClockRead(n) ||
  (n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && keyIs(n.callee, /^(getTime|valueOf)$/) && isClockRead(unwrap(n.callee.object)));

// A loop that reads the clock and does nothing else: no await and no call besides the clock itself (a `throw new Error()` is how it
// ends, not work). A body with an await or a call is a poll and stays legal. The test and update decide the loop when they read the clock.
// A read in the body counts when it ends the loop or writes what the test reads:
//   - an `if` on the clock (directly or through a variable or `box.t`) with a break, return or throw in either branch at any depth,
//     or a `continue` beside a break after it (`while (true) { if (Date.now() < end) continue; break; }`);
//   - an `if` on the clock, or a plain assignment from it, that writes a variable the test reads (`while (!done) { done = Date.now() > end; }`).
// `for (let i = 0; i < 3; i++) stamps[i] = Date.now();` records times, and `if (Date.now() > d) late++` counts them: neither waits.
function isBusyWait(loop) {
  const parts = [loop.test, loop.update, loop.body].filter(Boolean);
  const nodes = parts.flatMap((n) => [n, ...descendants(n)]);
  const inThrow = (n) => {
    for (let up = n.parent; up && up !== loop; up = up.parent) if (up.type === 'ThrowStatement') return true;
    return false;
  };
  if (nodes.some((n) => n.type === 'AwaitExpression' || ((n.type === 'CallExpression' || n.type === 'NewExpression') && !isClock(n) && !inThrow(n)))) return false;
  const head = [loop.test, loop.update].filter(Boolean).flatMap((n) => [n, ...descendants(n)]);
  if (head.some(isClockRead)) return true;
  const body = [loop.body, ...descendants(loop.body)];
  const target = (n) => (n.type === 'VariableDeclarator' ? n.id : n.type === 'AssignmentExpression' ? n.left : n.type === 'UpdateExpression' ? n.argument : null);
  const place = (n) => {
    const t = n && unwrap(n);
    return t && (t.type === 'Identifier' || t.type === 'MemberExpression') ? pathOf(t) : null;
  };
  // Places holding a clock read: `const t = Date.now()`, `t = performance.now()`, `box.t = Date.now()`, and what is computed from them.
  const fed = new Set();
  const feeds = (expr) => !!expr && [expr, ...descendants(expr)].some((t) => isClockRead(t) || ((t.type === 'Identifier' || t.type === 'MemberExpression') && fed.has(pathOf(t))));
  // One pass: a place is fed when a write to it reads the clock or reads a fed place, so reverse the reads and walk outward from the clocks.
  const readers = new Map();
  const queue = [];
  for (const n of body) {
    tick();
    const path = place(target(n));
    const expr = n.type === 'VariableDeclarator' ? n.init : n.right;
    if (n.type === 'UpdateExpression' || !path || !expr) continue;
    const parts = [expr, ...descendants(expr)];
    if (parts.some(isClockRead)) {
      if (!fed.has(path)) {
        fed.add(path);
        queue.push(path);
      }
      continue;
    }
    for (const t of parts) {
      if (t.type !== 'Identifier' && t.type !== 'MemberExpression') continue;
      const read = pathOf(t);
      if (!readers.has(read)) readers.set(read, new Set());
      readers.get(read).add(path);
    }
  }
  while (queue.length) {
    tick();
    for (const path of readers.get(queue.pop()) ?? []) {
      tick();
      if (fed.has(path)) continue;
      fed.add(path);
      queue.push(path);
    }
  }
  const tested = new Set(loop.test ? [loop.test, ...descendants(loop.test)].map(place) : []);
  const writesTest = (list) => list.some((n) => (n.type === 'AssignmentExpression' || n.type === 'UpdateExpression') && tested.has(place(target(n))));
  const leaves = (list) => list.some((n) => /^(BreakStatement|ReturnStatement|ThrowStatement)$/.test(n.type));
  const bodyLeaves = leaves(body);
  const decides = (branch) => {
    if (!branch) return false;
    const list = [branch, ...descendants(branch)];
    return leaves(list) || writesTest(list) || (bodyLeaves && list.some((n) => n.type === 'ContinueStatement'));
  };
  return body.some((n) => {
    if (n.type === 'IfStatement') return feeds(n.test) && (decides(n.consequent) || decides(n.alternate));
    return (n.type === 'AssignmentExpression' && tested.has(place(n.left)) && feeds(n.right)) || false;
  });
}

// The module is the same functions as the globals, plus promise and async-iterator forms of them.
const TIMERS_MODULE = '(node:)?timers(\\/promises)?';
const timersModule = new RegExp(`^${TIMERS_MODULE}$`);
// A module name the lint can read: a string, a template with no hole, or a name holding one (each write counts). A template
// with a hole still starts with its static head: `timers${x}` and `timers/${x}` can load the timers module, while
// `timers-browserify${x}` is another package.
const TIMERS_HEAD = /^(node:)?timers(\/|$)/;
function namesTimers(arg) {
  arg = unwrap(arg);
  return (arg.type === 'Identifier' ? constInits(arg) : [arg]).some((value) => {
    value = unwrap(value);
    if (value.type === 'TemplateLiteral' && value.expressions.length) return TIMERS_HEAD.test(value.quasis[0].value.cooked);
    return timersModule.test(literalKey(value) ?? '');
  });
}

const noSleepApi = {
  meta: {
    type: 'problem',
    schema: [],
    messages: {
      driver: `waitForTimeout is a fixed sleep in the browser driver. ${SIGNALS}`,
      scheduler: `scheduler.wait is a sleep. ${SIGNALS}`,
      atomics: `Atomics.wait and Atomics.waitAsync block or wait for a fixed time. ${SIGNALS}`,
      script: `A script string that sets a timer sleeps inside the page. ${SIGNALS}`,
      busy: `A loop that only spins on the clock is a busy-wait sleep. ${SIGNALS}`,
      timers: `node:timers and timers/promises hide sleeps behind aliases and async iterators. ${SIGNALS}`,
    },
  },
  create(context) {
    current = context;
    const loop = (node) => {
      if (isBusyWait(node)) context.report({ node, messageId: 'busy' });
    };
    // `const e = eval; e(...)` and `const F = Function; F(...)` run script text under another name.
    const calleeNames = (callee) => {
      if (callee.type === 'MemberExpression') return keysOf(callee);
      return callee.type === 'Identifier' && isHostRef(callee, ['eval', 'Function']) ? [callee.name, 'eval'] : [callee.name];
    };
    const scripts = (node, names) => {
      if (!names.some((name) => SCRIPT_CALLS.has(name))) return;
      if (node.arguments.some((arg) => /\bset(Timeout|Interval)\b/.test(scriptText(arg)) || setsTimer(arg))) context.report({ node, messageId: 'script' });
    };
    return {
      MemberExpression(node) {
        if (keyIs(node, /^waitForTimeout$/)) context.report({ node, messageId: 'driver' });
        else if (keyIs(node, /^wait$/) && isHostRef(node.object, ['scheduler'])) context.report({ node, messageId: 'scheduler' });
        else if (keyIs(node, /^wait(Async)?$/) && isHostRef(node.object, ['Atomics'])) context.report({ node, messageId: 'atomics' });
      },
      // `const { waitForTimeout: w } = page`, `const { wait } = Atomics`, `const { wait } = scheduler`
      Property(node) {
        if (node.parent.type !== 'ObjectPattern') return;
        const keys = propKeys(node);
        if (keys.includes('waitForTimeout')) return context.report({ node, messageId: 'driver' });
        const from = sourceOf(node.parent);
        if (!from) return;
        if (keys.includes('wait') && isHostRef(from, ['scheduler'])) context.report({ node, messageId: 'scheduler' });
        else if (keys.some((k) => /^wait(Async)?$/.test(k)) && isHostRef(from, ['Atomics'])) context.report({ node, messageId: 'atomics' });
      },
      // `import('timers')`, ``import(`node:timers`)`` and `const m = 'timers'; import(m)`: a selector only reads a plain string.
      ImportExpression(node) {
        if (namesTimers(node.source)) context.report({ node, messageId: 'timers' });
      },
      CallExpression(node) {
        const callee = unwrap(node.callee);
        const names = calleeNames(callee);
        // Only a bare `require`: `module.require` and `createRequire(...)` stay in the Known gaps.
        const loads = (callee.type === 'Identifier' && callee.name === 'require') || (callee.type === 'MemberExpression' && names.includes('getBuiltinModule'));
        if (loads && node.arguments[0] && namesTimers(node.arguments[0])) {
          return context.report({ node, messageId: 'timers' });
        }
        scripts(node, names);
      },
      // `new Function('setTimeout(r, 5)')`
      NewExpression(node) {
        const callee = unwrap(node.callee);
        scripts(node, calleeNames(callee));
      },
      WhileStatement: loop,
      DoWhileStatement: loop,
      ForStatement: loop,
    };
  },
};

// The bare name only. A member (`globalThis.setTimeout`, `g.setTimeout`) is the real timer only when its object is a host, and a
// selector cannot tell a host from `opts`, so the alias rule judges members it is handed (`use(opts.setTimeout)` is a config read).
const TIMER = 'Identifier[name=/^set(Timeout|Interval)$/]';
const PROMISIFY = ":matches([callee.name='promisify'], [callee.property.name='promisify'])";
// Asserting on or typing the real timer is not scheduling anything with it.
// The call is `expect(x)` or a matcher on one (`expect(x).toBe(...)`, `.not.`, `.resolves.`, `expect.soft(x)`), `assert.*`, or `vi.mocked`.
const MATCHER_ARMS = [1, 2, 3].flatMap((depth) => {
  const call = `callee${'.object'.repeat(depth)}`;
  return [`[${call}.callee.name=/^expect/]`, `[${call}.callee.object.name='expect']`];
});
const INSPECTS = `:matches([callee.name=/^(expect|assert)/], [callee.object.name=/^assert/], [callee.object.object.name=/^assert/], ${MATCHER_ARMS.join(', ')}, [callee.object.name='vi'][callee.property.name=/^(isMockFunction|mocked)$/])`;
// Selector, then what it is. A promise executor that calls a timer directly is
// the custom rule above and aliasing setTimeout is the second one; these cover the
// sleeps that never build a Promise in the test body: helpers, promisified timers,
// and setTimeout held as a value.
// An import or re-export of the module that loads it at run time. `import type { Timeout } from 'node:timers'` and a declaration whose
// every specifier is `type` (`import { type Timeout } from ...`) load nothing, so they are legal; one value specifier, a default or
// namespace import, an `export *` or a bare `import 'timers'` still load it.
const TIMERS_FROM = `[source.value=/^${TIMERS_MODULE}$/]`;
const TIMERS_LOADS =
  `ImportDeclaration${TIMERS_FROM}:not([importKind='type']):matches(:not(:has(ImportSpecifier)), :has(ImportSpecifier[importKind!='type']), :has(ImportDefaultSpecifier), :has(ImportNamespaceSpecifier)), ` +
  `:matches(ExportNamedDeclaration, ExportAllDeclaration)${TIMERS_FROM}:not([exportKind='type']):matches(:not(:has(ExportSpecifier)), :has(ExportSpecifier[exportKind!='type']))`;

const BANNED = [
  ["FunctionDeclaration[id.name='sleep'], VariableDeclarator[id.name='sleep']", 'No sleep helper in tests'],
  [`CallExpression${PROMISIFY} > ${TIMER}`, 'promisify(setTimeout) is a sleep'],
  [
    `:matches(CallExpression, NewExpression):not(${PROMISIFY}):not(${INSPECTS}) > ${TIMER}.arguments`,
    'setTimeout passed as a value is a sleep in disguise',
  ],
  [
    `:matches(CallExpression, NewExpression):not(${PROMISIFY}):not(${INSPECTS}) > :matches(TSAsExpression, TSNonNullExpression, TSSatisfiesExpression, TSTypeAssertion).arguments > ${TIMER}.expression`,
    'setTimeout passed as a value behind a cast is a sleep in disguise',
  ],
  [`${TIMERS_LOADS}, TSImportEqualsDeclaration:not([importKind='type']) > TSExternalModuleReference[expression.value=/^${TIMERS_MODULE}$/]`, 'node:timers and timers/promises hide sleeps behind aliases and async iterators'],
];

// The files the sleep rules and the banned selectors apply to.
const TEST_FILES = ['tests/**/*.{ts,tsx,mts}'];

// A block that sets `no-restricted-syntax` replaces the options an earlier block set, so appending the banned selectors alone would drop
// every selector the host repo already restricts in tests. A block's `files` is matched against sample test paths: a block that covers all
// of them (no `files`, a catch-all glob, the test glob) has its entries kept in front of the banned ones; a block that covers none (a
// JavaScript-only glob, `src/**`) never applies to a test and is left alone; a block that covers some (`tests/**/*.ts`, `**/*.test.ts`, or a
// glob with `ignores` cutting into it) would be dropped or widened by a merge, so it throws and is merged by hand.
const SAMPLES = ['ts', 'tsx', 'mts'].flatMap((ext) => [`tests/a.${ext}`, `tests/lint/a.test.${ext}`, `tests/e2e/deep/a.${ext}`]);
const braces = (glob) => {
  const open = /\{([^{}]*)\}/.exec(glob);
  return open ? open[1].split(',').flatMap((alt) => braces(glob.slice(0, open.index) + alt + glob.slice(open.index + open[0].length))) : [glob];
};
// `**/` is any directories (or none), `*` and `?` stay inside one name, the rest is literal.
const GLOB_PARTS = { '**/': '(?:.*/)?', '/**': '(?:/.*)?', '**': '.*', '*': '[^/]*', '?': '[^/]' };
const matches = (glob, path) =>
  braces(glob.replace(/^\.\//, '').replace(/\/$/, '/**')).some((g) =>
    new RegExp(`^${g.replace(/[.+^$()|[\]\\]/g, '\\$&').replace(/\*\*\/|\/\*\*$|\*\*|\*|\?/g, (t) => GLOB_PARTS[t])}$`).test(path),
  );
const coverOf = (block) => {
  if (!block.files) return 'all';
  const hit = SAMPLES.filter(
    (path) => block.files.some((f) => (Array.isArray(f) ? f.every((g) => matches(g, path)) : matches(f, path))) && !(block.ignores ?? []).some((g) => matches(g, path)),
  );
  return hit.length === SAMPLES.length ? 'all' : hit.length ? 'some' : 'none';
};
export function withNoSleep(blocks) {
  const own = blocks.flatMap((block) => {
    const list = block.rules?.['no-restricted-syntax'];
    if (!Array.isArray(list) || list.length < 2) return [];
    const cover = coverOf(block);
    if (cover === 'some') {
      throw new Error(`withNoSleep: a block for ${JSON.stringify(block.files)} sets no-restricted-syntax on some test files but not all of ${TEST_FILES}. Cover them all, or move the selectors into a block without \`files\`.`);
    }
    return cover === 'all' ? list.slice(1) : [];
  });
  return [
    ...blocks,
    {
      // Tests sync on a signal (vi.waitFor, fake timers, an awaited event), never a
      // fixed delay: a sleep that passes on an idle host fails once CI is busy.
      files: TEST_FILES,
      plugins: { local: { rules: { 'no-sleep-promise': noSleepPromise, 'no-timer-alias': noTimerAlias, 'no-sleep-api': noSleepApi } } },
      rules: {
        'local/no-sleep-promise': 'error',
        'local/no-timer-alias': 'error',
        'local/no-sleep-api': 'error',
        'no-restricted-syntax': [
          'error',
          ...own,
          ...BANNED.map(([selector, what]) => ({
            selector,
            message: `${what}. ${SIGNALS}`,
          })),
        ],
      },
    },
  ];
}
