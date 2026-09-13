(function() {
  var outline = document.getElementById('page-outline');
  if (!outline) return;

  var nav = outline.querySelector('.outline-links');
  var entries = Array.from(nav.querySelectorAll('a')).map(function(link) {
    return { link: link, heading: document.getElementById(decodeURIComponent(link.hash.slice(1))) };
  }).filter(function(entry) { return entry.heading; });
  if (!entries.length) return;

  var compact = window.matchMedia('(max-width: 900px)');
  var storageKey = 'sdme-outline-open';
  var header = document.querySelector('.site-header');
  var active = null;
  var scheduled = false;

  function restoreOpen() {
    var stored = null;
    try { stored = localStorage.getItem(storageKey); } catch(e) {}
    outline.open = !compact.matches && stored !== 'false';
  }

  function revealActive() {
    if (!active || !outline.open) return;
    if (nav.contains(document.activeElement) && document.activeElement.matches(':focus-visible')) return;
    var bounds = nav.getBoundingClientRect();
    var linkBounds = active.link.getBoundingClientRect();
    if (linkBounds.top < bounds.top) nav.scrollTop += linkBounds.top - bounds.top;
    else if (linkBounds.bottom > bounds.bottom) nav.scrollTop += linkBounds.bottom - bounds.bottom;
  }

  function update() {
    scheduled = false;
    var offset = header ? header.getBoundingClientRect().bottom + 32 : 32;
    var current = entries[0];
    entries.forEach(function(entry) {
      if (entry.heading.getBoundingClientRect().top <= offset) current = entry;
    });
    if (window.scrollY > 0 && window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) {
      current = entries[entries.length - 1];
    }
    if (current === active) return;
    if (active) active.link.removeAttribute('aria-current');
    active = current;
    active.link.setAttribute('aria-current', 'location');
    revealActive();
  }

  function scheduleUpdate() {
    if (scheduled) return;
    scheduled = true;
    window.requestAnimationFrame(update);
  }

  restoreOpen();
  outline.querySelector('summary').addEventListener('click', function() {
    if (!compact.matches) {
      try { localStorage.setItem(storageKey, String(!outline.open)); } catch(e) {}
    }
  });
  outline.addEventListener('toggle', revealActive);
  nav.addEventListener('click', function(event) {
    var link = event.target.closest('a');
    if (!link || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    if (compact.matches) outline.open = false;
  });
  compact.addEventListener('change', restoreOpen);
  window.addEventListener('scroll', scheduleUpdate, { passive: true });
  window.addEventListener('resize', scheduleUpdate);
  window.addEventListener('hashchange', scheduleUpdate);
  window.addEventListener('load', scheduleUpdate);
  scheduleUpdate();
})();
