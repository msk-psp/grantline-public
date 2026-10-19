import init from '/static/pkg/grantline_ui.js';
init().catch(() => {
  const note = document.createElement('p');
  note.className = 'notice error';
  note.setAttribute('role', 'alert');
  note.textContent = 'Interactive UI could not start. Refresh or contact the operator.';
  document.getElementById('grantline-app')?.prepend(note);
});
