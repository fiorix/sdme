(function() {
  var CACHE_KEY = 'sdme_release';
  var CACHE_TTL = 5 * 60 * 1000;

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

  // Expose cache helpers for downloads.js
  window._sdmeRelease = { getCached: getCached, setCache: setCache };

  var cached = getCached();
  if (cached) {
    showVersion(cached);
  } else {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://api.github.com/repos/fiorix/sdme/releases/latest');
    xhr.setRequestHeader('Accept', 'application/vnd.github.v3+json');
    xhr.onload = function() {
      if (xhr.status === 200) {
        try {
          var data = JSON.parse(xhr.responseText);
          setCache(data);
          showVersion(data);
          if (window._sdmeOnRelease) window._sdmeOnRelease(data);
        } catch(e) {}
      } else {
        if (window._sdmeOnReleaseFail) window._sdmeOnReleaseFail();
      }
    };
    xhr.onerror = function() {
      if (window._sdmeOnReleaseFail) window._sdmeOnReleaseFail();
    };
    xhr.send();
  }
})();
