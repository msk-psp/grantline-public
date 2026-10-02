// Resource-row hover must not dim the whole map each time the pointer enters or leaves.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const classList = () => {
  const classes = new Set();
  return {
    add: name => classes.add(name), remove: name => classes.delete(name),
    contains: name => classes.has(name),
    toggle(name, force) { if (force) classes.add(name); else classes.delete(name); },
  };
};
const svg = { classList: classList() };
const tip = { style: {} };
const map = { append() {}, getBoundingClientRect: () => ({ left: 0, top: 0 }) };
const source = readFileSync(new URL('../grantline/static/map.js', import.meta.url), 'utf8');
const hover = source.slice(source.indexOf("  const tip = document.createElement('div')"),
                          source.indexOf('  const nameOf ='));
const context = vm.createContext({ svg, map, document: { createElement: () => tip }, live: () => true });
const { light, unhover } = vm.runInContext(hover + '\n({ light, unhover })', context);
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
for (const key of ['nd:researcher_d', 'ed:researcher_d>group:product']) {
  light(key, [node], 'route', pointer);
  assert(svg.classList.contains('hovering'), 'node/edge hover still focuses its routes');
  light('row:projects/analytics', [row], 'analytics', pointer);
  assert.equal(svg.classList.contains('hovering'), false);
  assert.equal(node.classList.contains('hot'), false);
  unhover();
}
console.log('PASS: repeated row hover keeps context, node/edge hover and tooltip still work');
