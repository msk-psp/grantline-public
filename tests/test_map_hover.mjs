// Resource-row hover must not dim the whole map each time the pointer enters or leaves.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const tr = (message, ...values) => message.replace(/\{(\d+)\}/g, (_, i) => values[i]);
const classList = () => {
  const classes = new Set();
  const changes = [];
  return {
    changes,
    add(name) { changes.push(['add', name]); classes.add(name); },
    // DOMTokenList.remove can write class even when the token is absent.
    remove(name) { changes.push(['remove', name]); classes.delete(name); },
    contains: name => classes.has(name),
    toggle(name, force) {
      if (classes.has(name) !== force) changes.push(['toggle', name, force]);
      if (force) classes.add(name); else classes.delete(name);
    },
  };
};
const svg = { classList: classList() };
const tip = { style: {} };
const map = { append() {}, addEventListener() {}, getBoundingClientRect: () => ({ left: 0, top: 0 }) };
const source = readFileSync(new URL('../grantline/static/map.js', import.meta.url), 'utf8');
const hover = source.slice(source.indexOf("  const tip = document.createElement('div')"),
                          source.indexOf('  // ── camera'));
const account = { classList: classList(), dataset: { id: 'alice' } };
const holder = { classList: classList(), dataset: { id: 'group:product' } };
const unrelated = { classList: classList(), dataset: { id: 'bob' } };
const member = { classList: classList(), dataset: { src: 'alice', dst: 'group:product' } };
const connector = { classList: classList(), dataset: { src: 'group:product', row: 'projects' } };
const otherConnector = { classList: classList(), dataset: { src: 'bob', row: 'projects' } };
const context = vm.createContext({ tr, svg, map, document: { createElement: () => tip },
  nodes: [account, holder, unrelated], edges: [member], nodeById: new Map(), drag: null,
  resCol: { layer: { querySelectorAll: () => [connector, otherConnector] } },
  setTimeout, clearTimeout,
});
const { light, unhover, hover: onHover } = vm.runInContext(hover + '\n({ light, unhover, hover })', context);
const row = { classList: classList() }, node = { classList: classList() };
const pointer = { clientX: 100, clientY: 100 };

for (let i = 0; i < 5; i++) {
  light('row:projects/product', [row], 'product · via team-product', pointer);
  assert(row.classList.contains('hot'));
  assert.equal(tip.textContent, 'product · via team-product');
  assert.equal(tip.hidden, false);
  assert.equal(svg.classList.contains('hovering'), false, 'row hover must keep map context bright');
  unhover();
  assert.equal(row.classList.contains('hot'), false);
  assert.equal(tip.hidden, true);
}
assert.deepEqual(svg.classList.changes, [], 'row re-entry/leave must not mutate the whole SVG class');

// Moving straight from one resource row to another must not reset the SVG either.
const secondRow = { classList: classList() };
light('row:projects/product', [row], 'product', pointer);
light('row:projects/analytics', [secondRow], 'analytics', pointer);
assert.equal(row.classList.contains('hot'), false);
assert.equal(secondRow.classList.contains('hot'), true);
assert.deepEqual(svg.classList.changes, [], 'row-to-row hover must only update the rows');
unhover();

for (const key of ['nd:researcher_d', 'ed:researcher_d>group:product']) {
  light(key, [node], 'route', pointer);
  assert(svg.classList.contains('hovering'), 'node/edge hover still focuses its routes');
  light('row:projects/analytics', [row], 'analytics', pointer);
  assert.equal(svg.classList.contains('hovering'), false);
  assert.equal(node.classList.contains('hot'), false);
  unhover();
}
// Node-to-node hover must not remove/re-add the global focus in one event.
light('nd:one', [node], 'one', pointer);
svg.classList.changes.length = 0;
node.classList.changes.length = 0;
light('nd:two', [node], 'two', pointer);
assert.deepEqual(svg.classList.changes, [], 'global hovering stays enabled between nodes');
assert.deepEqual(node.classList.changes, [], 'shared highlights stay in place between targets');
unhover();

// Exercise the actual resource branch, including inherited access and selection limits.
const resource = { classList: classList(), dataset: { row: 'projects\u0000product', srcs: 'group:product' },
  querySelector: () => ({ textContent: 'product' }) };
resource.classList.add('on');
const resourcePointer = { ...pointer, target: { closest: () => resource } };
for (let i = 0; i < 5; i++) {
  onHover(resourcePointer);
  for (const el of [resource, account, holder, member, connector]) assert(el.classList.contains('hot'));
  for (const el of [unrelated, otherConnector]) assert.equal(el.classList.contains('hot'), false);
  assert.equal(svg.classList.contains('hovering'), false, 'resource feedback keeps the map stable');
  unhover();
  for (const el of [resource, account, holder, member, connector]) assert.equal(el.classList.contains('hot'), false);
}
svg.classList.add('focus');
holder.classList.add('on');
connector.classList.add('on');
onHover(resourcePointer);
assert.equal(account.classList.contains('hot'), false, 'selection-excluded account stays excluded');
assert(holder.classList.contains('hot'));
unhover();
svg.classList.remove('focus');

console.log('PASS: repeated resource hover highlights holders and inherited routes within the selection');

// API failures must not turn into empty access or a JSON exception from an SSO page.
const apiSource = source.slice(source.indexOf('  async function readData('), source.indexOf('  let data;'));
let response, redirected = '';
const apiContext = vm.createContext({ tr, fetch: async () => response,
  location: { pathname: '/', search: '?focus=alice', assign: url => { redirected = url; } } });
const readData = vm.runInContext(apiSource + '\nreadData', apiContext);
response = { status: 401 };
await assert.rejects(readData('/api/graph.json'), /Sign in/);
assert.equal(redirected, '/login?next=%2F%3Ffocus%3Dalice');
response = { status: 503, ok: false };
await assert.rejects(readData('/api/resources.json'), /Service request failed/);
response = { status: 200, ok: true, headers: { get: () => 'text/html' } };
await assert.rejects(readData('/api/graph.json'), /gateway returned a sign-in page/);
response = { status: 200, ok: true, headers: { get: () => 'application/json' }, json: () => ({ items: [] }) };
assert.deepEqual(await readData('/api/resources.json'), { items: [] });
console.log('PASS: expired sign-in, unavailable services and gateway HTML stay distinct from empty access');

// Run the actual enhancement script: focus is harmless; changing a proposal retires its preview.
const control = value => ({ value, attrs: {}, listeners: {},
  setAttribute(k, v) { this.attrs[k] = v; }, removeAttribute(k) { delete this.attrs[k]; },
  getAttribute(k) { return this.attrs[k]; }, addEventListener(k, fn) { this.listeners[k] = fn; } });
const fields = { system: control('s3'), subject: control('alice'), resource: control('bucket:demo'), priv: control('Read') };
fields.system.options = [{ value: '' }, { value: 'postgres' }, { value: 's3' }];
const proposalForm = control(''); proposalForm.elements = fields;
const preview = { hidden: false }, button = control('approve');
button.name = 'decision'; button.style = {};
const postForm = control(''); postForm.querySelectorAll = () => [button];
const windowEvents = {};
vm.runInNewContext(readFileSync(new URL('../grantline/static/console.js', import.meta.url), 'utf8'), {
  document: {
    querySelector: selector => selector === '.language select' ? null : selector === '#propose' ? proposalForm : preview,
    querySelectorAll: selector => ['form[method="post"]', 'form[aria-busy]'].includes(selector) ? [postForm] : [],
  }, addEventListener: (name, fn) => { windowEvents[name] = fn; },
});
assert.equal(fields.resource.value, 'bucket:demo');
assert.equal(fields.resource.attrs.list, 's1-resource');
assert.equal(fields.resource.listeners.focus, undefined, 'focus must not reset input');
fields.system.value = 'postgres'; fields.system.listeners.change(); proposalForm.listeners.change();
assert.equal(fields.subject.value, 'alice'); assert.equal(fields.resource.value, '');
assert.equal(fields.priv.value, ''); assert.equal(fields.resource.attrs.list, 's0-resource');
assert.equal(preview.hidden, true, 'the old command must disappear when the proposal changes');
let blocked = 0;
const submit = { preventDefault: () => { blocked++; } };
postForm.listeners.submit(submit); postForm.listeners.submit(submit);
assert.equal(blocked, 1); assert.equal(button.disabled, undefined);
assert.equal(button.name, 'decision'); assert.equal(button.value, 'approve');
windowEvents.pageshow(); assert.equal(postForm.attrs['aria-busy'], undefined);
console.log('PASS: form values, service suggestions, stale previews and duplicate-submit guard');

// Client placeholders and Unicode must survive the same catalogs used by the server.
for (const locale of ['en', 'ko', 'ja', 'zh-CN']) {
  const messages = locale === 'en' ? {} : JSON.parse(readFileSync(new URL(`../grantline/locales/${locale}.json`, import.meta.url), 'utf8'));
  const context = vm.createContext({ document: { querySelector: () => ({ textContent: JSON.stringify(messages) }) } });
  vm.runInContext(readFileSync(new URL('../grantline/static/i18n.js', import.meta.url), 'utf8'), context);
  const translated = context.GrantlineI18n('{0} of {1} rows', 2, 10);
  assert.equal(translated, (messages['{0} of {1} rows'] || '{0} of {1} rows').replace('{0}', 2).replace('{1}', 10));
  assert.equal(context.GrantlineI18n('via {0}', '<script>Read</script>'), (messages['via {0}'] || 'via {0}').replace('{0}', '<script>Read</script>'));
}
console.log('PASS: four client catalogs preserve Unicode and placeholder values');

// Environment identifiers become text, preserving custom names instead of translations.
const envButtons = [];
const envBox = { append(button) { envButtons.push(button); } };
const names = ['prod', 'staging', 'Read', '自定义 <script> " {0}'];
const environmentSource = source.slice(source.indexOf("  const envBox ="), source.indexOf("  const svcBox ="));
vm.runInNewContext(environmentSource, {
  data: { edges: names.map(name => ({ env: [name, name] })) },
  document: { querySelector: () => envBox, createElement: () => ({ dataset: {} }) }, tr,
});
assert.deepEqual(envButtons.map(button => button.textContent), [...names].sort());
assert.deepEqual(envButtons.map(button => button.dataset.env), [...names].sort());
assert(envButtons.every(button => !('innerHTML' in button)), 'environment data must never become HTML');
console.log('PASS: environment identifiers preserve literal names and custom scopes');

const envOn = new Set(names);
const filterSource = source.slice(source.indexOf('    const shown ='), source.indexOf('    for (const e of edges) e.classList.toggle'));
const shown = vm.runInNewContext(filterSource + '\nshown', { envOn, kindOn: new Set(['postgres']) });
for (const name of names) {
  const edge = { dataset: { env: JSON.stringify([name]), kind: 'postgres' } };
  assert(shown(edge), 'space and punctuation in environment names must remain filterable');
  envOn.delete(name); assert.equal(shown(edge), false); envOn.add(name);
}
