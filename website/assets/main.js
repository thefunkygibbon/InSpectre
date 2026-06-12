// InSpectre site — tiny progressive-enhancement helpers (no dependencies)
(function () {
  document.documentElement.classList.add('js');

  // Mobile window-list toggle
  var toggle = document.querySelector('.nav-toggle');
  var links = document.querySelector('.sb-windows');
  if (toggle && links) {
    toggle.addEventListener('click', function () { links.classList.toggle('open'); });
  }

  // Copy-to-clipboard — hero/CTA install blocks (.copy-btn → .install code)
  document.querySelectorAll('.copy-btn[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var code = btn.closest('.term').querySelector('.install code');
      copy(btn, code);
    });
  });

  // Copy-to-clipboard — content code blocks (.code-head button → .code code)
  document.querySelectorAll('.code-head button[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var code = btn.closest('.code').querySelector('code');
      copy(btn, code);
    });
  });

  function copy(btn, code) {
    var text = code ? code.innerText : '';
    navigator.clipboard.writeText(text).then(function () {
      var old = btn.textContent;
      btn.textContent = 'copied!';
      setTimeout(function () { btn.textContent = old; }, 1500);
    });
  }

  // Live clock in the status bar
  var clock = document.getElementById('clock');
  function tick() { if (clock) clock.textContent = new Date().toTimeString().slice(0, 8); }
  tick(); setInterval(tick, 1000);

  // Year in footer
  var yr = document.getElementById('yr');
  if (yr) yr.textContent = new Date().getFullYear();

  // Reveal-on-scroll
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
    });
  }, { threshold: 0.12 });
  document.querySelectorAll('[data-reveal]').forEach(function (el) { io.observe(el); });
})();
