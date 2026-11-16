// SA2 Scan: tabs, drag-and-drop upload, report polling, key reveal/copy, HUD auto-refresh.
document.querySelectorAll('.tabs').forEach(bar => {
  bar.addEventListener('click', e => {
    const btn = e.target.closest('.tab'); if (!btn) return;
    bar.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b === btn));
    const scope = bar.parentElement;
    scope.querySelectorAll(':scope > .tabpane').forEach(p => p.classList.toggle('active', p.id === btn.dataset.tab));
  });
});

const form = document.getElementById('upload-form');
if (form) {
  const input = document.getElementById('file-input');
  const send = () => { document.getElementById('upload-busy').hidden = false; form.submit(); };
  input.addEventListener('change', () => input.files.length && send());
  ['dragover', 'dragenter'].forEach(t => document.addEventListener(t, e => { e.preventDefault(); form.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(t => document.addEventListener(t, () => form.classList.remove('over')));
  document.addEventListener('drop', e => { e.preventDefault(); if (e.dataTransfer.files.length) { input.files = e.dataTransfer.files; send(); } });
}

const rep = document.querySelector('.report');
if (rep && ['queued', 'scanning'].includes(rep.dataset.status)) {
  const poll = async () => {
    try {
      const r = await fetch(`/file/${rep.dataset.sha}/status`);
      const j = await r.json();
      if (!['queued', 'scanning'].includes(j.status)) return location.reload();
    } catch (_) { /* server restarting; keep polling */ }
    setTimeout(poll, 1000);
  };
  poll();
}
if (rep && rep.dataset.print) window.addEventListener('load', () => setTimeout(() => window.print(), 300));

document.querySelectorAll('[data-reveal]').forEach(b => b.addEventListener('click', () => {
  const el = document.getElementById(b.dataset.reveal);
  const shown = el.textContent === el.dataset.secret;
  el.textContent = shown ? '••••••••••••••••' : el.dataset.secret;
  b.textContent = shown ? 'Show' : 'Hide';
}));
document.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', async () => {
  const el = document.getElementById(b.dataset.copy);
  try { await navigator.clipboard.writeText(el.dataset.secret || el.textContent); b.textContent = 'Copied'; }
  catch (_) { b.textContent = 'Copy failed'; }
  setTimeout(() => (b.textContent = 'Copy'), 1500);
}));

const auto = document.querySelector('[data-autorefresh]');
if (auto) setTimeout(() => location.reload(), 1000 * +auto.dataset.autorefresh);
