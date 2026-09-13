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
    var button = document.getElementById('theme-toggle');
    if (button) {
      var label = 'Switch to ' + (theme === 'dark' ? 'light' : 'dark') + ' theme';
      button.setAttribute('aria-label', label);
      button.title = label;
    }
  }

  applyTheme(getPreferredTheme());

  document.addEventListener('DOMContentLoaded', function() {
    applyTheme(getPreferredTheme());
    document.getElementById('theme-toggle').addEventListener('click', function() {
      var current = document.documentElement.getAttribute('data-theme') || 'dark';
      var next = current === 'dark' ? 'light' : 'dark';
      try { localStorage.setItem(THEME_KEY, next); } catch(e) {}
      applyTheme(next);
    });
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
