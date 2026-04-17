(function() {
  var CACHE_KEY = 'sdme_release';
  var CACHE_TTL = 5 * 60 * 1000;
  var API_URL = 'https://api.github.com/repos/fiorix/sdme/releases/latest';

  function getCached() {
    try {
      var raw = sessionStorage.getItem(CACHE_KEY);
      if (!raw) return null;
      var cached = JSON.parse(raw);
      if (Date.now() - cached.ts > CACHE_TTL) {
        sessionStorage.removeItem(CACHE_KEY);
        return null;
      }
      return cached.data;
    } catch(e) { return null; }
  }

  function setCache(data) {
    try {
      sessionStorage.setItem(CACHE_KEY, JSON.stringify({ ts: Date.now(), data: data }));
    } catch(e) {}
  }

  function showVersion(release) {
    var badge = document.getElementById('version-badge');
    badge.textContent = release.tag_name;
    badge.style.display = 'inline-block';
  }

  var cached = getCached();
  if (cached) {
    showVersion(cached);
    window._sdmeRelease = { getCached: getCached, fetched: Promise.resolve(cached) };
    return;
  }

  var fetched = fetch(API_URL, { headers: { 'Accept': 'application/vnd.github.v3+json' } })
    .then(function(res) {
      if (!res.ok) throw new Error(res.status);
      return res.json();
    })
    .then(function(data) {
      setCache(data);
      showVersion(data);
      return data;
    });

  // Expose cache + in-flight promise so other scripts reuse the same request
  window._sdmeRelease = { getCached: getCached, fetched: fetched };
})();
