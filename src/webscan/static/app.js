// SA2 Scan console behaviour. No framework; everything degrades to plain links and forms.
(() => {
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];

  // theme
  const root = document.documentElement;
  $$('[data-theme-toggle]').forEach(b => b.addEventListener('click', () => {
    const dark = root.dataset.theme !== 'light';  // dark is the default theme
    root.dataset.theme = dark ? 'light' : 'dark';
    try { localStorage.setItem('sa2-theme', root.dataset.theme); } catch (e) { /* private mode */ }
  }));

  // tabs (remember the last one per page)
  $$('.tabs').forEach(bar => {
    const key = 'sa2-tab-' + location.pathname.split('/')[1];
    const show = id => {
      $$('button', bar).forEach(b => b.classList.toggle('on', b.dataset.tab === id));
      $$('.tabpane').forEach(p => p.classList.toggle('on', p.id === id));
    };
    bar.addEventListener('click', e => {
      const b = e.target.closest('button[data-tab]'); if (!b) return;
      show(b.dataset.tab);
      try { sessionStorage.setItem(key, b.dataset.tab); } catch (err) { /* ignore */ }
    });
    try { const last = sessionStorage.getItem(key); if (last && document.getElementById(last)) show(last); } catch (err) { /* ignore */ }
  });

  // clickable table rows
  document.addEventListener('click', e => {
    const tr = e.target.closest('tr[data-href]');
    if (tr && !e.target.closest('a, button, input, select, form')) location.href = tr.dataset.href;
  });

  // copy / reveal
  const copy = async (text, btn) => {
    try { await navigator.clipboard.writeText(text); btn.dataset.old ??= btn.innerHTML; btn.textContent = 'Copied'; }
    catch (e) { btn.textContent = 'Copy failed'; }
    setTimeout(() => { if (btn.dataset.old) btn.innerHTML = btn.dataset.old; }, 1400);
  };
  $$('[data-copy]').forEach(b => b.addEventListener('click', () => copy(b.dataset.copy, b)));
  $$('[data-copy-from]').forEach(b => b.addEventListener('click', () => copy(document.getElementById(b.dataset.copyFrom).dataset.secret, b)));
  $$('[data-reveal]').forEach(b => b.addEventListener('click', () => {
    const el = document.getElementById(b.dataset.reveal);
    const shown = el.textContent === el.dataset.secret;
    el.textContent = shown ? '••••••••••••••••••••••••' : el.dataset.secret;
  }));

  // upload: pick or drop a file and submit
  const form = document.getElementById('upload-form');
  if (form) {
    const input = document.getElementById('file-input');
    const drop = form.querySelector('.drop');
    const send = () => { document.getElementById('upload-busy').hidden = false; form.submit(); };
    input.addEventListener('change', () => input.files.length && send());
    ['dragenter', 'dragover'].forEach(t => document.addEventListener(t, e => { e.preventDefault(); drop.classList.add('over'); }));
    ['dragleave', 'drop'].forEach(t => document.addEventListener(t, e => { if (t === 'drop' || !e.relatedTarget) drop.classList.remove('over'); }));
    document.addEventListener('drop', e => {
      e.preventDefault();
      if (e.dataTransfer.files.length) { input.files = e.dataTransfer.files; send(); }
    });
  }

  // report: wait for the scan, then reload; print view
  const rep = document.getElementById('report');
  if (rep && ['queued', 'scanning'].includes(rep.dataset.status)) {
    const poll = async () => {
      try {
        const j = await (await fetch(`/file/${rep.dataset.sha}/status`)).json();
        if (!['queued', 'scanning'].includes(j.status)) return location.reload();
      } catch (e) { /* server restarting */ }
      setTimeout(poll, 1000);
    };
    poll();
  }
  if (rep && rep.dataset.print) {
    document.body.classList.add('printing');
    window.addEventListener('load', () => setTimeout(() => window.print(), 400));
  }

  // live pages
  const live = document.querySelector('[data-autorefresh]');
  if (live) setTimeout(() => { if (!document.hidden) location.reload(); }, 1000 * +live.dataset.autorefresh);
})();
