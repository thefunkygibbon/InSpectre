// InSpectre site — tiny progressive-enhancement helpers (no dependencies)
(function () {
  // Enable JS-only enhancements (e.g. reveal-on-scroll hiding)
  document.documentElement.classList.add('js');

  // Mobile nav toggle
  var toggle = document.querySelector('.nav-toggle');
  var links = document.querySelector('.nav-links');
  if (toggle && links) {
    toggle.addEventListener('click', function () {
      links.classList.toggle('open');
    });
  }

  // Copy-to-clipboard for code blocks
  document.querySelectorAll('.code-head button[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var pre = btn.closest('.code').querySelector('code');
      var text = pre ? pre.innerText : '';
      navigator.clipboard.writeText(text).then(function () {
        var old = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(function () { btn.textContent = old; }, 1500);
      });
    });
  });

  // Reveal-on-scroll
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
    });
  }, { threshold: 0.12 });
  document.querySelectorAll('[data-reveal]').forEach(function (el) { io.observe(el); });
})();
