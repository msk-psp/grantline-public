// The routes map. Data comes from /api/graph.json (see web.graph_data); this file
// decides where things go and how they move. No dependencies, no build — an ES
// module the page loads as-is.
//
//   layout   one column per kind, rows a–z, resources collapsed onto instances
//   camera   translate+scale on the <svg> (composited: no re-layout per frame)
//   focus    click a node → its routes stay, everything else fades, camera glides
//   env      prod / staging toggles hide edges, then nodes nothing reaches

const COL = 350, ROW = 48, W = 270, H = 32, TOP = 150, ARR = 7;  // W fits `clinical-researcher  prod·stg 🌿`
const LANE = 40;            // y of the bus above the columns that long edges travel on
const SVC_ORDER = ['postgres', 'clickhouse', 's3'];
const svgNS = 'http://www.w3.org/2000/svg';
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElementNS(svgNS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null) n.setAttribute(k, v);
  for (const k of kids) n.append(k);
  return n;
};
const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');

async function main() {
  const svg = document.querySelector('svg.gr'); if (!svg) return;
  const map = svg.parentElement;
  // The shell is served without waiting for the read (web.do_GET), so the placeholder
  // stands until this answers. Every exit below removes it — a map that failed must not
  // keep saying it is loading.
  const done = () => map.querySelector('p.loading')?.remove();
  const stop = msg => { done(); map.insertAdjacentHTML('afterbegin',
    `<p class="loading">${esc(msg)}</p>`); };
  let res;
  try { res = await fetch('/api/graph.json' + location.search); }
  catch (err) { stop(`could not read the services: ${err}`); return; }
  if (!res.ok) { stop(`could not load the map (${res.status}) — nothing below is drawn`); return; }
  const data = await res.json();
  done();
  // F6 on the map. A system that could not be read draws no lines, and a map with no
  // lines into it looks exactly like a system nobody can reach. Say which, and why,
  // before the picture — the picture is incomplete and the reader must know it.
  const note = document.querySelector('.blind');
  if (note && data.blind && data.blind.length) {
    note.innerHTML = '<div class="warn stop"><b>the map is incomplete</b>'
      + data.blind.map(b => `${esc(b.system)} could not be read (${esc(b.note)})`).join('; ')
      + '. Nothing below shows a route into it. That is not "nobody reaches it" — it is '
      + 'unknown, and the two must not be read as the same thing.</div>';
  }
  if (!data.nodes.length) { map.innerHTML = '<p class=ok>No multi-hop authority — every grant is direct.</p>'; return; }

  // ── layout ───────────────────────────────────────────────────────────
  // Humans and declared services both *consume* authority — one column, with a
  // header row between them, rather than a near-empty column for two services.
  const colKey = n => n.kind === 'service' ? 'human' : n.kind;
  const cols = data.columns.filter(k => k !== 'service' && data.nodes.some(n => colKey(n) === k));
  const TITLE = { human: 'principal', instance: 'resources in' };
  // Who *uses* an account: the declared service a bridge departs from. One hop
  // further, the roles that account holds directly — `airflow_analytics` is Airflow's
  // role as much as `airflow` is its login. Not further: PUBLIC is nobody's.
  const nodeById = new Map(data.nodes.map(n => [n.id, n]));
  const usedBy = new Map();
  const add = (id, svc) => { const set = usedBy.get(id) || new Set(); set.add(svc); usedBy.set(id, set); };
  for (const e of data.edges) if (e.cls === 'bridge' && e.src.startsWith('service:')) add(e.dst, e.src);
  for (const e of data.edges) if (e.cls === 'e-member' && usedBy.has(e.src) && !usedBy.has(e.dst) && nodeById.get(e.dst)?.kind === 'role')
    for (const svc of usedBy.get(e.src)) add(e.dst, svc);
  // Accounts, roles, groups and policies are sorted by the service they live in
  // (postgres, clickhouse, s3 — a node in several goes with the first), a–z inside,
  // with a small header row where the service changes. Humans and instances stay a–z.
  const svcOf = n => {
    const ks = new Set((n.homes || []).map(h => (data.instances[h] || {}).kind));
    return SVC_ORDER.find(k => ks.has(k)) || [...ks][0] || '';
  };
  const GROUPED = new Set(['svc-account', 'role', 'group', 'policy']);
  // what a column groups its rows by: the service they live in, or (principals) their kind
  // principal 열: 사람은 팀별로, 그다음 선언된 서비스. 팀은 관측으로 알 수 없어
  // 설정이 말한다 (`[graph.teams]`); 없으면 종류(human/service)로만 나뉜다.
  const teamOf = n => n.kind === 'human' ? (n.team || '') : '';
  const teamNames = [...new Set(data.nodes.map(teamOf).filter(Boolean))].sort();
  const groupOf = (k, n) => GROUPED.has(k) ? svcOf(n)
    : k === 'human' ? (n.kind === 'service' ? 'service' : teamOf(n) || 'human') : '';
  const groupRank = (k, n) => GROUPED.has(k) ? SVC_ORDER.indexOf(svcOf(n))
    : k === 'human' ? (n.kind === 'service' ? 99 : teamOf(n) ? teamNames.indexOf(teamOf(n)) : 98) : 0;
  const byCol = new Map(cols.map(k => [k, data.nodes.filter(n => colKey(n) === k).sort((a, b) =>
    groupRank(k, a) - groupRank(k, b) || a.sort.localeCompare(b.sort))]));
  const pos = new Map(), heads = [];      // heads: [x, y, group, icon] rows to caption
  let rowsMax = 0;
  cols.forEach((k, i) => {
    let row = 0, last = null;
    for (const n of byCol.get(k)) {
      const g = groupOf(k, n);
      if (g && g !== last) {
        last = g;
        const icon = GROUPED.has(k) ? g : g === 'service' ? 'app' : 'person';
        heads.push([60 + COL * i, TOP + ROW * row, g, icon]); row++;
      }
      pos.set(n.id, [60 + COL * i, TOP + ROW * row]); row++;
    }
    rowsMax = Math.max(rowsMax, row);
  });
  const width = 60 + COL * cols.length + W;
  const height = TOP + 20 + ROW * rowsMax;
  const colOf = x => Math.round((x - 60) / COL);
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

  // Where a role, group or account lives — the column says what it is, the small
  // icons at its right edge say in which services, and a text tag says the
  // environment when it is not simply production. Hover for the full names.
  const homeIcons = g => {   // returns the x where a text tag may end
    const kinds = [...new Set((g.homes || []).map(h => (data.instances[h] || {}).kind).filter(Boolean))];
    const envs = new Set((g.homes || []).flatMap(h => (data.instances[h] || {}).env || []));
    return { kinds, tag: envs.has('staging') ? (envs.has('prod') ? 'prod·stg' : 'stg') : '' };
  };

  // ── draw ─────────────────────────────────────────────────────────────
  const frag = document.createDocumentFragment();
  const defs = el('defs'); defs.innerHTML =
    '<marker id="arr" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto" markerUnits="userSpaceOnUse">' +
    '<path d="M0,0.5 L8,4 L0,7.5 z" fill="context-stroke"/></marker>';
  frag.append(defs);
  cols.forEach((k, i) => {
    const x = 60 + COL * i;
    frag.append(el('text', { class: 'ch', x, y: TOP - 30 }, TITLE[k] || data.titles[k] || k));
    frag.append(el('text', { class: 'cs', x, y: TOP - 14 },
      `${byCol.get(k).length} · ${GROUPED.has(k) ? 'by service, a–z'
        : k === 'human' ? (teamNames.length ? 'by team, then services' : 'humans, then services, a–z') : 'a–z'}`));
  });
  for (const [x, y, name, icon] of heads) {
    const g = el('g', { class: `gh i-${icon}`, transform: `translate(${x},${y + 8})` });
    const ic = el('g', { class: 'ic', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.4, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' });
    ic.innerHTML = data.icons[icon] || data.icons.generic; g.append(ic);
    g.append(el('text', { class: 'cs', x: 22, y: 12 }, name || 'other'));
    frag.append(g);
  }
  // An edge that skips a column would run straight through the boxes in between and
  // read as theirs. Those travel on a lane above the columns instead.
  const route = (x1, y1, x2, y2) => {
    const mid = (x1 + x2) / 2;
    // x1 is a box's right edge, x2 a box's left edge less the arrowhead
    const c1 = Math.round((x1 - W - 60) / COL), c2 = Math.round((x2 + ARR - 60) / COL);
    if (c2 - c1 === 1) return `M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`;
    // rise in the source's gutter, run along the lane, drop in the destination's
    // gutter — the gutters are the 80 px between columns, where no box is
    const G = COL - W, r = G / 2;
    return `M${x1},${y1} C${x1 + r},${y1} ${x1 + r},${LANE} ${x1 + G},${LANE} ` +
           `L${x2 - G},${LANE} C${x2 - r},${LANE} ${x2 - r},${y2} ${x2},${y2}`;
  };
  const edges = [], labels = [];
  for (const e of data.edges) {
    if (!pos.has(e.src) || !pos.has(e.dst)) continue;
    let [x1, y1] = pos.get(e.src), [x2, y2] = pos.get(e.dst);
    const back = x2 < x1;                              // right-to-left: a role bridging onto a key
    x1 += back ? 0 : W; x2 += back ? W + ARR : -ARR; y1 += H / 2; y2 += H / 2;
    const mid = (x1 + x2) / 2, env = e.env.join(' ');
    const p = el('path', { class: e.cls === 'bridge' ? 'bridge' : `ed ${e.cls}`, 'marker-end': 'url(#arr)',
                           'data-env': env, 'data-kind': e.kind || '', 'data-src': e.src, 'data-dst': e.dst,
                           'data-what': e.what || '', d: route(x1, y1, x2, y2) });
    edges.push(p); frag.append(p);
    if (e.label) {
      const t = el('text', { class: 'bl', 'data-env': env, 'data-kind': e.kind || '', 'data-src': e.src, 'data-dst': e.dst,
                             x: mid, y: (y1 + y2) / 2 - 6, 'text-anchor': 'middle' }, e.label);
      labels.push(t); frag.append(t);
    }
  }
  const nodes = [];
  for (const n of data.nodes) {
    const [x, y] = pos.get(n.id);
    const g = el('g', { class: `nd ${n.kind}`, 'data-id': n.id, tabindex: 0 },
                 el('rect', { x, y, width: W, height: H, rx: 9 }));
    if (n.icon) {
      const ic = el('g', { class: `ic i-${n.icon}`, transform: `translate(${x + 10},${y + 7})`, fill: 'none',
                           stroke: 'currentColor', 'stroke-width': 1.4, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' });
      ic.innerHTML = data.icons[n.icon] || data.icons.generic; g.append(ic);
    }
    const nameEl = el('text', { x: x + (n.icon ? 34 : 12), y: y + 20 }, n.label);
    g.append(nameEl);
    if (n.tag) g.append(el('text', { class: 'fo', x: x + W - 12, y: y + 20, 'text-anchor': 'end' }, n.tag));
    else if (n.homes?.length) {
      const { kinds, tag } = homeIcons(n);
      // strip, right to left: where it lives (service kinds), then who uses it
      const users = [...(usedBy.get(n.id) || [])];
      const userIcons = [...new Set(users.map(u => nodeById.get(u)?.icon || 'app'))];
      const strip = [...kinds.map(k => ['i-' + k, data.icons[k]]),
                     ...userIcons.map(ic => ['i-' + ic + ' used', data.icons[ic]])];
      strip.forEach(([cls, inner], i) => {
        const ic = el('g', { class: `ic ${cls}`, transform: `translate(${x + W - 24 - 18 * i},${y + 8}) scale(.8)`, fill: 'none',
                             stroke: 'currentColor', 'stroke-width': 1.6, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' });
        ic.innerHTML = inner || data.icons.generic; g.append(ic);
      });
      const tagX = x + W - 28 - 18 * strip.length;
      if (tag) g.append(el('text', { class: 'fo', x: tagX, y: y + 20, 'text-anchor': 'end' }, tag));
      // shorten the name if the strip and tag leave it no room (7 px per monospace char)
      const room = (tag ? tagX - 6.6 * tag.length - 8 : tagX) - (+nameEl.getAttribute('x'));
      const fits = Math.floor(room / 7.1);
      if (fits > 3 && n.label.length > fits) { nameEl.textContent = n.label.slice(0, fits - 1) + '…'; g.append(el('title', {}, n.label)); }
      g.append(el('title', {}, `in: ${n.homes.join(', ')}` + (users.length ? `\nused by: ${users.map(u => u.slice(8)).join(', ')}` : '')));
    }
    nodes.push(g); frag.append(g);
  }
  svg.replaceChildren(frag);

  // ── hover: which line is under the cursor ────────────────────────────
  // A 1.2 px curve is not a pointer target, and one invisible fat path per edge
  // would double the DOM (687 paths already). Instead each edge keeps a handful of
  // sampled points and the cursor finds the nearest — 300 edges × 9 samples is a
  // few thousand comparisons, cheaper than a hit-test through the SVG tree.
  for (const p of edges) {
    const len = p.getTotalLength(), n = Math.max(6, Math.min(24, Math.round(len / 60))), pts = [];
    for (let i = 0; i <= n; i++) { const q = p.getPointAtLength(len * i / n); pts.push(q.x, q.y); }
    p.__pts = pts;
  }
  // distance² from a point to the polyline through those samples — the segments
  // matter, not the samples: a curve sampled every 60 units is a straight line
  // between them to within a pixel, and 10 samples of points would miss the gaps.
  function distTo(pts, px, py, best) {
    for (let i = 0; i < pts.length - 2; i += 2) {
      const ax = pts[i], ay = pts[i + 1], bx = pts[i + 2], by = pts[i + 3];
      const vx = bx - ax, vy = by - ay, wx = px - ax, wy = py - ay;
      const vv = vx * vx + vy * vy;
      const t = vv ? Math.max(0, Math.min(1, (wx * vx + wy * vy) / vv)) : 0;
      const dx = wx - t * vx, dy = wy - t * vy, d = dx * dx + dy * dy;
      if (d < best) best = d;
    }
    return best;
  }
  const tip = document.createElement('div'); tip.className = 'tip'; tip.hidden = true; map.append(tip);
  let hot = null;                 // { key, els: [] } — everything wearing .hot now
  const drawn = el => live(el) && (!svg.classList.contains('focus') || el.classList.contains('on'));
  function unhover() {
    if (!hot) return;
    for (const el of hot.els) el.classList.remove('hot');
    if (svg.classList.contains('hovering')) svg.classList.remove('hovering');
    hot = null; tip.hidden = true;
  }
  function light(key, els, text, ev) {
    const r = map.getBoundingClientRect();
    const place = () => { tip.style.left = (ev.clientX - r.left + 12) + 'px'; tip.style.top = (ev.clientY - r.top + 12) + 'px'; };
    if (hot?.key === key) return place();
    // Keep shared highlights in place; resetting the whole SVG retriggers its transitions.
    for (const el of hot?.els || []) if (!els.includes(el)) el.classList.remove('hot');
    for (const el of els) if (!el.classList.contains('hot')) el.classList.add('hot');
    // Resource rows describe the selected routes; keep that context bright on enter/leave.
    svg.classList.toggle('hovering', !key.startsWith('row:'));
    hot = { key, els };
    tip.textContent = text; tip.hidden = false; place();
  }
  const nameOf = id => nodeById.get(id)?.label ?? id.replace(/^(@|service:)/, '');
  function hover(ev) {
    if (drag?.moved) return unhover();
    // A node under the cursor wins: its own lines, and nothing else. That holds
    // inside a selection too — the selection says which routes exist, the hover
    // says which of them touch this one box.
    const g = ev.target.closest?.('g.nd');
    if (g && drawn(g)) {
      const id = g.dataset.id;
      if (!id) {   // a row in the resources column: say who reaches it, and how
        const name = g.querySelector('text').textContent.replace(/^[▸▾]\s*/, '');
        const via = g.dataset.via ? `  ·  via ${g.dataset.via}` : '';
        return light('row:' + g.dataset.row, [g], name + via, ev);
      }
      const mine = edges.filter(e => drawn(e) && (e.dataset.src === id || e.dataset.dst === id));
      const ends = new Set(mine.map(e => e.dataset.src === id ? e.dataset.dst : e.dataset.src));
      const inn_ = mine.filter(e => e.dataset.dst === id).length;
      // the rows this box feeds — the whole point of a bridge is that the resources
      // arrive through somebody else's key, and the column must say so
      const rows = [...resCol.layer.querySelectorAll('.rs')].filter(r => (r.dataset.srcs || '').split('\u0000').includes(id));
      return light('nd:' + id, [g, ...mine, ...nodes.filter(n => ends.has(n.dataset.id)), ...rows],
                   `${nameOf(id)}  ·  ${inn_} in, ${mine.length - inn_} out` +
                   (rows.length ? `  ·  ${rows.length} resource row(s)` : ''), ev);
    }
    const r = map.getBoundingClientRect(), u = r.width / fitW * cam.k;
    const ux = (ev.clientX - r.left - cam.x) / u, uy = (ev.clientY - r.top - cam.y) / u;
    const near = 9 / u;                       // 9 css px, in svg units
    let best = null, bestD = near * near;
    for (const p of edges) {
      if (!drawn(p)) continue;
      const d = distTo(p.__pts, ux, uy, bestD);
      if (d < bestD) { bestD = d; best = p; }
    }
    if (!best) return unhover();
    const ends = nodes.filter(n => n.dataset.id === best.dataset.src || n.dataset.id === best.dataset.dst);
    light('ed:' + best.dataset.src + '>' + best.dataset.dst, [best, ...ends],
          `${nameOf(best.dataset.src)} → ${nameOf(best.dataset.dst)}  ·  ${best.dataset.what || ''}`, ev);
  }
  // 커서가 멈춘 다음에야 하이라이트를 바꾼다. 선 하나를 스칠 때마다 다시 그리면
  // 화면을 가로지르는 동안 수십 번 전환이 겹쳐 눈이 못 따라간다. 마지막 위치
  // 하나만 반영하는 trailing debounce — 지나친 것은 계산조차 하지 않는다.
  const DWELL = 110;
  let dwell = 0;
  function onMove(ev) {
    clearTimeout(dwell);
    if (drag?.moved) return unhover();
    const at = { clientX: ev.clientX, clientY: ev.clientY, target: ev.target };
    dwell = setTimeout(() => hover(at), DWELL);
  }
  function leave() { clearTimeout(dwell); unhover(); }
  map.addEventListener('pointermove', onMove);
  map.addEventListener('pointerleave', leave);

  // ── adjacency ─────────────────────────────────────────────────────────
  const out = {}, inn = {};
  for (const e of edges) { (out[e.dataset.src] ||= []).push(e); (inn[e.dataset.dst] ||= []).push(e); }
  const live = e => !e.classList.contains('off');
  function walk(start, table, pick) {
    const seenN = new Set([start]), seenE = new Set(), stack = [start];
    while (stack.length) {
      const n = stack.pop();
      for (const e of table[n] || []) {
        if (!live(e)) continue;
        seenE.add(e); const next = pick(e);
        if (!seenN.has(next)) { seenN.add(next); stack.push(next); }
      }
    }
    return [seenN, seenE];
  }

  // ── camera ────────────────────────────────────────────────────────────
  const fitW = width;
  let cam = { x: 0, y: 0, k: 1 }, home = { x: 0, y: 0, k: 1 };
  // Zoom and glide are CSS transitions, not per-frame JS. Measured (1865×1273 css px,
  // dpr 2, 687 paths, 242 texts): a JS-driven scale re-rasterises the whole layer
  // every frame — 50 ms/frame, 15 fps. A compositor-driven transition scales the
  // bitmap it already has and re-rasterises once at rest. Pan stays JS-driven:
  // translate does not re-rasterise (16.7 ms/frame measured).
  const EASE = 'cubic-bezier(.22,.61,.36,1)';
  function apply(ms = 0) {
    svg.style.transition = ms ? `transform ${ms}ms ${EASE}` : 'none';
    svg.style.transform = `translate(${cam.x}px,${cam.y}px) scale(${cam.k})`;
  }
  function glide(to, ms = 360) { cam = { ...to }; apply(ms); }
  function zoomAt(factor, px, py) {
    const k = Math.max(0.35, Math.min(12, cam.k * factor)), f = k / cam.k;
    cam = { x: px - (px - cam.x) * f, y: py - (py - cam.y) * f, k }; apply(140);
  }
  const local = ev => { const r = map.getBoundingClientRect(); return [ev.clientX - r.left, ev.clientY - r.top]; };
  map.addEventListener('wheel', ev => { ev.preventDefault(); const [px, py] = local(ev); zoomAt(ev.deltaY > 0 ? 1 / 1.12 : 1.12, px, py); }, { passive: false });

  // A press that moves is a pan; one that does not is a click on what was under it.
  let drag = null;
  map.addEventListener('pointerdown', ev => {
    if (ev.button !== 0 || ev.target.closest('.zoom')) return;
    drag = { x: ev.clientX, y: ev.clientY, cam: { ...cam }, moved: false, node: ev.target.closest('.nd') };
  });
  map.addEventListener('pointermove', ev => {
    if (!drag) return;
    if (!drag.moved && Math.abs(ev.clientX - drag.x) + Math.abs(ev.clientY - drag.y) > 4) {
      drag.moved = true; map.classList.add('dragging'); svg.classList.add('moving'); map.setPointerCapture(ev.pointerId);
    }
    if (!drag.moved) return;
    cam = { ...cam, x: drag.cam.x + ev.clientX - drag.x, y: drag.cam.y + ev.clientY - drag.y }; apply();
  });
  map.addEventListener('pointerup', () => {
    if (!drag) return;
    const d = drag; drag = null; map.classList.remove('dragging'); svg.classList.remove('moving');
    if (d.moved) return;
    if (d.node?.classList.contains('rs')) { if (d.node.dataset.key) resCol.toggle(d.node.dataset.key); }
    else if (d.node) pick(d.node.dataset.id);
    else if (sel.length) focus(null);
  });
  map.addEventListener('pointercancel', () => { drag = null; map.classList.remove('dragging'); svg.classList.remove('moving'); });
  for (const b of document.querySelectorAll('.tools button[data-z]')) b.addEventListener('click', () => {
    const r = map.getBoundingClientRect(), cx = r.width / 2, cy = r.height / 2;
    if (b.dataset.z === 'in') zoomAt(1.4, cx, cy);
    else if (b.dataset.z === 'out') zoomAt(1 / 1.4, cx, cy);
    else glide(home);
  });
  function frameOf(els) {
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const n of els) {
      const r = n.firstChild, x = +r.getAttribute('x'), y = +r.getAttribute('y');
      x0 = Math.min(x0, x); y0 = Math.min(y0, y); x1 = Math.max(x1, x + W); y1 = Math.max(y1, y + H);
    }
    const pad = 70, bw = x1 - x0 + pad * 2, bh = y1 - y0 + pad * 2;
    const R = map.getBoundingClientRect(), u = R.width / fitW;
    const k = Math.max(0.35, Math.min(2.5, Math.min(R.width / (bw * u), R.height / (bh * u))));
    return { k, x: R.width / 2 - (x0 + x1) / 2 * u * k, y: R.height / 2 - (y0 + y1) / 2 * u * k };
  }

  // ── filters: environment and service. An edge is drawn while its environment
  //    and its service are both on; a node while one of its edges is. Bridges with
  //    no service of their own (system "*") follow whatever is on.
  const svcBox = document.querySelector('.tools .svc');
  const kinds = [...new Set(Object.values(data.instances).map(i => i.kind))].sort();
  for (const k of kinds) {
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'on'; b.dataset.kind = k; b.title = `show what reaches ${k}`;
    b.innerHTML = `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" class="ic i-${k}">${data.icons[k] || data.icons.generic}</svg>${k}`;
    svcBox.append(b);
  }
  const btns = attr => [...document.querySelectorAll(`.tools button[data-${attr}]`)];
  const active = attr => new Set(btns(attr).filter(b => b.classList.contains('on')).map(b => b.dataset[attr]));
  function applyFilters() {
    leave();
    const envOn = active('env'), kindOn = active('kind');
    const shown = e => e.dataset.env.split(' ').some(v => envOn.has(v)) && (!e.dataset.kind || kindOn.has(e.dataset.kind));
    for (const e of edges) e.classList.toggle('off', !shown(e));
    for (const t of labels) t.classList.toggle('off', !shown(t));
    const alive = new Set();
    for (const e of edges) if (live(e)) { alive.add(e.dataset.src); alive.add(e.dataset.dst); }
    for (const n of nodes) n.classList.toggle('off', !alive.has(n.dataset.id));
    if (sel.length) show(true); else resCol.render();
  }
  for (const attr of ['env', 'kind']) for (const b of btns(attr)) b.addEventListener('click', () => {
    if (b.classList.contains('on') && active(attr).size === 1) return;   // keep one on
    b.classList.toggle('on'); applyFilters();
  });

  // ── focus: a selection is a *stack* of nodes, and what is lit is what lies on a
  //    route through every one of them. Picking a lit node narrows (push); picking
  //    the same node again widens back to what was there before (pop); picking a
  //    node outside the lit set starts over from it. Esc, or empty space, clears.
  //    So the reader walks: a person → one of their roles → one of its buckets,
  //    and can step back one hop at a time instead of losing the whole trail.
  const sel = [];
  let litIds = null;                 // null = nothing selected (everything counts)
  const reach = id => {              // nodes and edges on any route through `id`
    const [dn, de] = walk(id, out, e => e.dataset.dst);
    const [un, ue] = walk(id, inn, e => e.dataset.src);
    return [new Set([...dn, ...un]), new Set([...de, ...ue])];
  };
  function show(keep = false) {
    leave();          // the highlight described the previous selection
    for (const x of [...nodes, ...edges, ...labels]) x.classList.remove('on', 'sel');
    svg.classList.toggle('focus', sel.length > 0);
    if (!sel.length) { litIds = null; resCol.render(); glide(home); return; }
    let ns = null, es = null;
    for (const id of sel) {
      const [n, e] = reach(id);
      ns = ns ? new Set([...ns].filter(x => n.has(x))) : n;
      es = es ? new Set([...es].filter(x => e.has(x))) : e;
    }
    const lit = nodes.filter(n => ns.has(n.dataset.id) && live(n));
    litIds = new Set(lit.map(n => n.dataset.id));
    for (const n of lit) n.classList.add('on');
    resCol.render();
    for (const n of nodes) if (sel.includes(n.dataset.id)) n.classList.add('sel');
    for (const e of es) e.classList.add('on');
    for (const t of labels) if ([...es].some(e => e.dataset.src === t.dataset.src && e.dataset.dst === t.dataset.dst)) t.classList.add('on');
    if (!keep) refit();
  }
  // Frame what matters now: the lit nodes (all of them when nothing is picked) plus
  // the resources column when it is open — it sits past the viewBox on purpose.
  // Bring what matters into view with the least motion: no move if it is already
  // visible, a pan if it is off to one side, a zoom-out only if it cannot fit.
  function reveal(els) {
    if (!els.length) return;
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const n of els) {
      const r = n.firstChild, x = +r.getAttribute('x'), y = +r.getAttribute('y');
      x0 = Math.min(x0, x); y0 = Math.min(y0, y); x1 = Math.max(x1, x + W); y1 = Math.max(y1, y + H);
    }
    const R = map.getBoundingClientRect(), u = R.width / fitW, pad = 24;
    let k = cam.k;
    const need = Math.min(R.width / ((x1 - x0) * u + pad * 2), R.height / ((y1 - y0) * u + pad * 2));
    if (need < k) k = Math.max(0.35, need);                 // zoom out just enough
    const s = u * k;
    const sx0 = x0 * s + cam.x, sx1 = x1 * s + cam.x, sy0 = y0 * s + cam.y, sy1 = y1 * s + cam.y;
    let dx = 0, dy = 0;
    if (sx0 < pad) dx = pad - sx0; else if (sx1 > R.width - pad) dx = R.width - pad - sx1;
    if (sy0 < pad) dy = pad - sy0; else if (sy1 > R.height - pad) dy = R.height - pad - sy1;
    if (k !== cam.k) {  // re-centre when the zoom changed
      const cx = (x0 + x1) / 2 * s, cy = (y0 + y1) / 2 * s;
      glide({ k, x: R.width / 2 - cx, y: R.height / 2 - cy }, 300);
    } else if (dx || dy) glide({ ...cam, x: cam.x + dx, y: cam.y + dy }, 260);
  }
  function refit() {
    const base = litIds ? nodes.filter(n => litIds.has(n.dataset.id)) : [];
    const extra = [...resCol.layer.querySelectorAll('.nd')];
    reveal([...base, ...extra]);
  }
  function pick(id) {
    if (!id) return;
    if (id.startsWith('@')) resCol.open(id.slice(1));
    const i = sel.indexOf(id);
    if (i >= 0) sel.splice(i, 1);                                              // step back
    else if (!sel.length || nodes.find(n => n.dataset.id === id)?.classList.contains('on')) sel.push(id);  // narrow
    else sel.splice(0, sel.length, id);                                        // start over
    show();
  }
  function focus(id, keep = false) {   // kept for the env toggles and ?focus=
    if (id === null) sel.length = 0; else if (!sel.includes(id)) sel.push(id);
    show(keep);
  }
  for (const n of nodes) n.addEventListener('keydown', ev => {
    if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); pick(n.dataset.id); }
  });

  // ── resources: the column the instance nodes fold away, unfolded one level at a
  //    time. `db:analytics` › `schema:analytics.silver` › `table:analytics.silver.beats`, and
  //    `bucket:projects/research/...` › prefix. Only what the current selection reaches.
  const resCol = {
    instance: null, items: [], layer: el('g', { class: 'res' }),
    x: 60 + COL * cols.length, cache: {}, open_: new Set(),
    parts(r) {                       // resource id → segments (db, schema, table / bucket, prefix…)
      const i = r.indexOf(':'), kind = r.slice(0, i), rest = r.slice(i + 1);
      if (kind === 'bucket') return rest === '*' ? ['*'] : rest.split('/');
      if (kind === 'default') { const [scope, by] = rest.split('@'); return [...scope.split('.'), 'defaults', `by ${by}`]; }   // fold under one row
      if (kind === 'global' || kind === 'capability') return [`${kind} ${rest}`];
      return rest.split('.');
    },
    async open(instance) {
      if (this.instance === instance) { this.close(); return; }
      this.instance = instance; this.open_ = new Set();
      if (!this.cache[instance]) {
        const r = await fetch('/api/resources.json?instance=' + encodeURIComponent(instance));
        this.cache[instance] = r.ok ? (await r.json()).items.map(i => ({ ...i, parts: this.parts(i.res) })) : [];
      }
      this.items = this.cache[instance]; this.render(); refit();
    },
    close() { this.instance = null; this.items = []; this.layer.replaceChildren(); },
    toggle(key) { this.open_.has(key) ? this.open_.delete(key) : this.open_.add(key); this.render(); },
    // The tree, shown two levels deep (db › schema; bucket › prefix) with the third
    // (tables) folded under its schema until clicked — 851 rows is not a map.
    render() {
      this.layer.replaceChildren();
      if (!this.instance) return;
      const x = this.x, ORDER = { none: 0, read: 1, write: 2, admin: 3 };
      const here = this.items.filter(i => litIds === null || litIds.has(i.src));
      const root = { kids: new Map(), n: 0, bySrc: new Map(), depth: -1 };
      const worse = (a, b) => ORDER[a] >= ORDER[b] ? a : b;
      for (const i of here) {
        let node = root;
        node.n++;
        for (let d = 0; d < i.parts.length; d++) {
          const seg = i.parts[d];
          if (!node.kids.has(seg)) node.kids.set(seg, { name: seg, kids: new Map(), n: 0, bySrc: new Map(), depth: d, key: i.parts.slice(0, d + 1).join('\u0000') });
          node = node.kids.get(seg); node.n++;
          node.bySrc.set(i.src, worse(i.level, node.bySrc.get(i.src) || 'none'));
        }
      }
      const rows = [];                                   // visible, in order
      const walk = (node, force) => {
        const kids = [...node.kids.values()].sort((a, b) => b.n - a.n || a.name.localeCompare(b.name));
        for (const k of kids) {
          rows.push(k);
          const show = k.depth < 1 || this.open_.has(k.key);   // depth 0,1 open; deeper on click
          if (k.kids.size && show) walk(k);
        }
      };
      walk(root);
      const CAP = 80, shown = rows.slice(0, CAP);
      const head = el('text', { class: 'ch', x, y: TOP - 30 }, this.instance + '  ');
      const allKeys = []; (function collect(n) { for (const k of n.kids.values()) { if (k.kids.size && k.depth >= 1) allKeys.push(k.key); collect(k); } })(root);
      const allOpen = allKeys.length && allKeys.every(k => this.open_.has(k));
      const ex = el('tspan', { class: 'crumb' }, allOpen ? '⊟ fold' : '⊞ expand all');
      ex.addEventListener('pointerup', ev => { ev.stopPropagation(); this.open_ = allOpen ? new Set() : new Set(allKeys); this.render(); });
      head.append(ex, el('tspan', {}, '   '));
      const close = el('tspan', { class: 'crumb' }, '× close'); close.addEventListener('pointerup', ev => { ev.stopPropagation(); this.close(); });
      head.append(close);
      this.layer.append(head);
      this.layer.append(el('text', { class: 'cs', x, y: TOP - 14 }, `${here.length} res · ${rows.length} rows${rows.length > CAP ? ` · showing ${CAP}` : ''}`));
      if (!here.length) {
        const who = sel.filter(id => !id.startsWith('@')).map(id => id.replace(/^[a-z]+:/, '')).join(' + ');
        this.layer.append(el('text', { class: 'cs', x, y: TOP + 20 },
          who ? `${who} reaches nothing in ${this.instance} — step back (Esc) to see all of it` : 'nothing collapsed here'));
      }
      const from = id => { const [nx, ny] = pos.get(id) || [x - COL, TOP]; return [nx + W, ny + H / 2]; };
      // lines land on top-level rows only; deeper rows say their grade in the tag
      shown.forEach((k, j) => {
        if (k.depth) return;
        const y = TOP + ROW * j;
        for (const [src, lv] of k.bySrc) {
          if (!pos.has(src)) continue;
          const [x1, y1] = from(src), x2 = x - ARR, y2 = y + H / 2;
          this.layer.append(el('path', { class: `ed on e-${lv}`, 'marker-end': 'url(#arr)', d: route(x1, y1, x2, y2) }));
        }
      });
      shown.forEach((k, j) => {
        const y = TOP + ROW * j, ind = 16 * k.depth;
        const worst = [...k.bySrc.values()].reduce(worse, 'none');
        const folded = k.kids.size && k.depth >= 1 && !this.open_.has(k.key);
        const openable = k.kids.size && k.depth >= 1;
        const via = [...k.bySrc].map(([src, lv]) => `${src} (${lv})`).join(', ');
        const node = el('g', { class: `nd on rs d${k.depth} ${openable ? 'deeper' : ''}`, 'data-key': openable ? k.key : null,
                               'data-row': k.key, 'data-srcs': [...k.bySrc.keys()].join('\u0000'), 'data-via': via },
                        el('rect', { x: x + ind, y, width: W - ind, height: H, rx: 9 }),
                        el('text', { x: x + ind + 12, y: y + 20 }, (k.depth ? (folded ? '▸ ' : openable ? '▾ ' : '') : '') + k.name),
                        el('text', { class: `fo e-${worst}`, x: x + W - 12, y: y + 20, 'text-anchor': 'end' },
                           `${k.kids.size ? k.kids.size + ' · ' : ''}${worst}`));
        this.layer.append(node);
      });
      if (rows.length > CAP) this.layer.append(el('text', { class: 'cs', x, y: TOP + ROW * CAP + 20 }, `+${rows.length - CAP} more — see the subject page`));
    },
  };
  svg.append(resCol.layer);
  document.addEventListener('keydown', ev => { if (ev.key === 'Escape') focus(null); });

  apply();
  const pre = new URLSearchParams(location.search).get('focus');
  if (pre) { const hit = nodes.find(n => n.dataset.id === pre) || nodes.find(n => n.dataset.id.includes(pre)); if (hit) focus(hit.dataset.id); }
}

main();
