// Demo navigation shared by all three sites. Copied into each site's public/
// folder by `npm run sync-assets`; edit this file, not the copies.
//
// * Fills <nav id="demo-nav"> with links to the three demo sites.
// * Points any <a data-site="agent|ps|board" data-path="..."> at that site.
//
// Links to another demo site open in a named tab per site ("aauth-board", ...),
// so clicking the board twice reuses the board tab instead of piling up tabs.
(() => {
  const SITES = [
    { id: 'agent', label: 'Agent', key: 'agentUrl' },
    { id: 'ps', label: 'Person Server', key: 'psUrl' },
    { id: 'board', label: 'Message Board', key: 'boardUrl' },
  ];
  const REPO = 'https://github.com/wjgilmore/aauth-demo';
  const here = document.body.dataset.role;

  /** Tab name for a demo site; exposed for links the pages build themselves. */
  window.demoTarget = (id) => `aauth-${id}`;

  // Claim this site's tab name, so links from the other sites reuse this tab
  // even if the visitor opened it by typing the URL.
  if (here && !window.name) window.name = window.demoTarget(here);

  function link(text, href, target) {
    const a = document.createElement('a');
    a.textContent = text;
    a.href = href;
    if (target) a.target = target;
    return a;
  }

  function render(config) {
    const nav = document.getElementById('demo-nav');
    if (nav) {
      nav.replaceChildren();
      const title = document.createElement('span');
      title.className = 'demo-title';
      title.textContent = 'AAuth demo';
      nav.append(title);
      for (const s of SITES) {
        if (s.id === here) {
          const cur = document.createElement('span');
          cur.className = 'current';
          cur.setAttribute('aria-current', 'page');
          cur.textContent = s.label;
          nav.append(cur);
        } else if (config[s.key]) {
          nav.append(link(s.label, config[s.key], window.demoTarget(s.id)));
        }
      }
      nav.append(link('GitHub ↗', REPO, '_blank'));
    }

    for (const a of document.querySelectorAll('a[data-site]')) {
      const s = SITES.find((x) => x.id === a.dataset.site);
      if (!s || !config[s.key]) continue;
      a.href = config[s.key] + (a.dataset.path || '');
      if (s.id !== here) a.target = window.demoTarget(s.id);
    }
  }

  window.demoConfig = fetch('/api/config')
    .then((r) => r.json())
    .catch(() => ({}))
    .then((config) => {
      if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => render(config));
      else render(config);
      return config;
    });
})();
