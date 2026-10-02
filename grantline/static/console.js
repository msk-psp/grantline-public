// Progressive enhancements: ordinary links and forms still work without JavaScript.
for (const link of document.querySelectorAll('.refresh')) {
  const url = new URL(location.href);
  url.searchParams.set('refresh', '1');
  link.href = url.pathname + url.search;
}

for (const [i, table] of [...document.querySelectorAll('table')].entries()) {
  const rows = [...table.tBodies].flatMap(body => [...body.rows]);
  if (!rows.length) continue;
  const name = table.closest('section')?.querySelector('h2')?.textContent.trim() || 'Rows';
  const bar = document.createElement('div'); bar.className = 'table-tools';
  const label = document.createElement('label'); label.textContent = 'Search ' + name;
  const input = document.createElement('input'); input.type = 'search';
  input.placeholder = 'Account, resource or privilege';
  label.append(input);
  const status = document.createElement('span'); status.id = 'filter-status-' + i;
  status.setAttribute('role', 'status'); input.setAttribute('aria-describedby', status.id);
  const clear = document.createElement('button'); clear.type = 'button'; clear.textContent = 'Clear';
  clear.addEventListener('click', () => { input.value = ''; filter(); input.focus(); });
  bar.append(label, clear, status); table.closest('.scroll').before(bar);
  const scroll = table.closest('.scroll');
  scroll.tabIndex = 0; scroll.setAttribute('role', 'region'); scroll.setAttribute('aria-label', name + ' table');
  function filter() {
    const query = input.value.trim().toLocaleLowerCase();
    let count = 0;
    for (const row of rows) {
      row.hidden = !row.textContent.toLocaleLowerCase().includes(query);
      if (!row.hidden) count++;
      for (const details of row.querySelectorAll('.more-chips')) details.open = !!query && !row.hidden;
    }
    status.textContent = count ? `${count} of ${rows.length} rows` : 'No matching rows. Try another search.';
    clear.disabled = !query;
  }
  input.addEventListener('input', filter); filter();
}

const form = document.querySelector('#propose');
if (form) {
  const service = form.elements.system;
  function sync(changed = false) {
    const option = [...service.options].filter(o => o.value).findIndex(o => o.value === service.value);
    for (const name of ['subject', 'resource', 'priv']) {
      const input = form.elements[name];
      if (option >= 0) input.setAttribute('list', `s${option}-${name}`);
      else input.removeAttribute('list');
      if (changed && name !== 'subject') input.value = '';
    }
  }
  service.addEventListener('change', () => sync(true)); sync();
  // A changed proposal needs a new preview before its command can be submitted.
  const preview = document.querySelector('#preview');
  if (preview) {
    const stale = () => { preview.hidden = true; };
    form.addEventListener('input', stale); form.addEventListener('change', stale);
  }
}

for (const post of document.querySelectorAll('form[method="post"]')) {
  post.addEventListener('submit', event => {
    if (post.getAttribute('aria-busy') === 'true') { event.preventDefault(); return; }
    // Do not disable a decision button: its name/value belongs in the submitted body.
    for (const button of post.querySelectorAll('button')) {
      button.setAttribute('aria-disabled', 'true');
      button.style.pointerEvents = 'none';
    }
    post.setAttribute('aria-busy', 'true');
  });
}

for (const code of document.querySelectorAll('.cmd code, .req pre, header pre')) {
  const button = document.createElement('button'); button.type = 'button';
  button.className = 'copy-command'; button.textContent = 'Copy command';
  const status = document.createElement('span'); status.setAttribute('role', 'status');
  button.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(code.textContent); status.textContent = 'Copied'; }
    catch { status.textContent = 'Copy unavailable. Select the command text instead.'; }
  });
  const tools = document.createElement('div'); tools.className = 'command-tools';
  tools.append(button, status); code.after(tools);
}

addEventListener('pageshow', () => {
  for (const post of document.querySelectorAll('form[aria-busy]')) {
    post.removeAttribute('aria-busy');
    for (const button of post.querySelectorAll('button')) {
      button.removeAttribute('aria-disabled'); button.style.pointerEvents = '';
    }
  }
});
