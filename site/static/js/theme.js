(function() {
  var THEME_KEY = 'sdme-theme';

  function getPreferredTheme() {
    var stored = null;
    try { stored = localStorage.getItem(THEME_KEY); } catch(e) {}
    if (stored === 'light' || stored === 'dark') return stored;
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) return 'light';
    return 'dark';
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    document.getElementById('icon-sun').style.display = theme === 'dark' ? 'none' : 'inline';
    document.getElementById('icon-moon').style.display = theme === 'dark' ? 'inline' : 'none';
    try { localStorage.setItem(THEME_KEY, theme); } catch(e) {}
  }

  applyTheme(getPreferredTheme());

  document.getElementById('theme-toggle').addEventListener('click', function() {
    var current = document.documentElement.getAttribute('data-theme') || 'dark';
    applyTheme(current === 'dark' ? 'light' : 'dark');
  });

  if (window.matchMedia) {
    try {
      window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', function(e) {
        var stored = null;
        try { stored = localStorage.getItem(THEME_KEY); } catch(ex) {}
        if (!stored) applyTheme(e.matches ? 'light' : 'dark');
      });
    } catch(e) {}
  }
})();
