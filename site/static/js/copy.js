(function() {
  var ICON_COPY = '<svg viewBox="0 0 16 16"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 0 1 0 1.5h-1.5a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-1.5a.75.75 0 0 1 1.5 0v1.5A1.75 1.75 0 0 1 9.25 16h-7.5A1.75 1.75 0 0 1 0 14.25Z"></path><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0 1 14.25 11h-7.5A1.75 1.75 0 0 1 5 9.25Zm1.75-.25a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0 0-.25-.25Z"></path></svg>';
  var ICON_CHECK = '<svg viewBox="0 0 16 16"><path d="M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.75.75 0 0 1 1.06-1.06L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0Z"></path></svg>';

  function addCopyButtons() {
    document.querySelectorAll('pre').forEach(function(pre) {
      if (pre.parentNode.classList.contains('code-row')) return;
      if (pre.classList.contains('diagram')) return;
      var wrapper = document.createElement('div');
      wrapper.className = 'code-row';
      pre.parentNode.insertBefore(wrapper, pre);
      wrapper.appendChild(pre);
      var btn = document.createElement('button');
      btn.className = 'copy-btn';
      btn.innerHTML = ICON_COPY;
      btn.title = 'Copy';
      btn.addEventListener('click', function() {
        var text = pre.querySelector('code')
          ? pre.querySelector('code').textContent
          : pre.textContent;
        copyText(text.trim(), btn);
      });
      wrapper.appendChild(btn);
    });
  }

  function copyText(text, btn) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function() {
        showCopied(btn);
      }, function() {
        fallbackCopy(text, btn);
      });
    } else {
      fallbackCopy(text, btn);
    }
  }

  function fallbackCopy(text, btn) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); showCopied(btn); }
    catch(e) {}
    document.body.removeChild(ta);
  }

  function showCopied(btn) {
    btn.innerHTML = ICON_CHECK;
    btn.classList.add('copied');
    setTimeout(function() {
      btn.innerHTML = ICON_COPY;
      btn.classList.remove('copied');
    }, 2000);
  }

  // Expose for downloads.js to call after dynamic content
  window.addCopyButtons = addCopyButtons;

  addCopyButtons();
})();
