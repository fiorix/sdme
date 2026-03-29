(function() {
  function formatSize(bytes) {
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(0) + ' KB';
    return bytes + ' B';
  }

  function archLabel(filename) {
    if (/x86_64|amd64/.test(filename)) return 'x86_64';
    if (/aarch64|arm64/.test(filename)) return 'aarch64';
    return '';
  }

  function classify(name) {
    if (/^sdme-(x86_64|aarch64)-linux$/.test(name)) return 'binary';
    if (/\.deb$/.test(name)) return 'deb';
    if (/\.rpm$/.test(name)) return 'rpm';
    if (/\.pkg\.tar\.zst$/.test(name)) return 'pkg';
    if (name === 'SHA256SUMS') return 'checksum';
    return null;
  }

  var categories = [
    {
      type: 'binary',
      title: 'Static Binaries',
      distros: 'Any Linux distro',
      deps: 'Requires <strong>systemd &ge; 252</strong> and <strong>systemd-container</strong> at runtime',
      cmdTemplate: function(url, filename) {
        return 'curl -fSL -o /usr/local/bin/sdme ' + url + ' && chmod +x /usr/local/bin/sdme';
      }
    },
    {
      type: 'deb',
      title: '.deb Packages',
      distros: 'Debian, Ubuntu, and derivatives',
      deps: 'Dependencies auto-resolved: <strong>systemd (&ge; 252)</strong>, <strong>systemd-container</strong>. Suggests: qemu-utils, apparmor',
      cmdTemplate: function(url, filename) {
        return 'curl -fSLO ' + url + ' && sudo apt install ./' + filename;
      }
    },
    {
      type: 'rpm',
      title: '.rpm Packages',
      distros: 'Fedora, CentOS Stream, AlmaLinux, openSUSE, RHEL, and derivatives',
      deps: 'Dependencies auto-resolved: <strong>systemd &ge; 252</strong>, <strong>systemd-container</strong>',
      cmdTemplate: function(url, filename) {
        return 'curl -fSLO ' + url + ' && sudo dnf install ./' + filename;
      }
    },
    {
      type: 'pkg',
      title: '.pkg.tar.zst Packages',
      distros: 'Arch Linux, CachyOS, and derivatives',
      deps: 'Requires <strong>systemd &ge; 252</strong> (includes systemd-nspawn on Arch)',
      cmdTemplate: function(url, filename) {
        return 'curl -fSLO ' + url + ' && sudo pacman -U ' + filename;
      }
    }
  ];

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function renderDownloads(release) {
    var groups = {};
    var checksumUrl = null;
    release.assets.forEach(function(a) {
      var type = classify(a.name);
      if (!type) return;
      if (type === 'checksum') { checksumUrl = a.browser_download_url; return; }
      if (!groups[type]) groups[type] = [];
      groups[type].push(a);
    });

    Object.keys(groups).forEach(function(k) {
      groups[k].sort(function(a, b) {
        var aa = archLabel(a.name), bb = archLabel(b.name);
        if (aa === 'x86_64' && bb !== 'x86_64') return -1;
        if (bb === 'x86_64' && aa !== 'x86_64') return 1;
        return a.name.localeCompare(b.name);
      });
    });

    var html = '<h2>Downloads</h2>';

    categories.forEach(function(cat) {
      var assets = groups[cat.type];
      if (!assets || assets.length === 0) return;

      html += '<div class="card">';
      html += '<h3>' + cat.title + '</h3>';
      html += '<p class="distros">' + cat.distros + '</p>';
      html += '<p class="deps">' + cat.deps + '</p>';

      assets.forEach(function(a) {
        var arch = archLabel(a.name);
        html += '<div class="asset-row">';
        html += '<a href="' + a.browser_download_url + '">' + a.name + '</a>';
        html += '<span class="size">' + (arch ? arch + ' · ' : '') + formatSize(a.size) + '</span>';
        html += '</div>';
      });

      assets.forEach(function(a) {
        var cmd = cat.cmdTemplate(a.browser_download_url, a.name);
        html += '<pre><code>' + escapeHtml(cmd) + '</code></pre>';
      });

      html += '</div>';
    });

    if (checksumUrl) {
      html += '<p class="checksum-link"><a href="' + checksumUrl + '">SHA256SUMS</a></p>';
    }

    var section = document.getElementById('downloads');
    section.innerHTML = html;
    section.style.display = 'block';

    var fb = document.getElementById('fallback');
    if (fb) fb.style.display = 'none';

    if (window.addCopyButtons) window.addCopyButtons();
  }

  function showFallback() {
    var fb = document.getElementById('fallback-content');
    if (fb) fb.style.display = 'block';
  }

  // Use cached data from version-badge.js if available
  var helpers = window._sdmeRelease;
  if (helpers) {
    var cached = helpers.getCached();
    if (cached) {
      renderDownloads(cached);
      return;
    }
  }

  // Otherwise wait for the fetch callback
  window._sdmeOnRelease = renderDownloads;
  window._sdmeOnReleaseFail = showFallback;
})();
