/* Apotrope website — interaction layer. Capture-safe: all content is visible
   without JS; this only adds motion, reveal, and copy affordances. */
(function () {
  "use strict";

  /* ── Binary rain ─────────────────────────────────────────────────────────── */
  function binaryRain() {
    var host = document.getElementById("binRain");
    if (!host) return;
    var cols = Math.floor(window.innerWidth / 28);
    var frag = document.createDocumentFragment();
    for (var i = 0; i < cols; i++) {
      var span = document.createElement("div");
      var len = 16 + Math.floor(Math.random() * 22), txt = "";
      for (var j = 0; j < len; j++) txt += (Math.random() > 0.5 ? "1" : "0") + " ";
      span.textContent = txt.trim();
      span.style.cssText =
        "position:absolute;top:-40%;left:" + ((i / cols) * 100) + "%;" +
        "writing-mode:vertical-rl;font-family:'IBM Plex Mono',monospace;font-size:12px;" +
        "line-height:1.1;color:#0d6b3f;opacity:" + (0.10 + Math.random() * 0.14) + ";" +
        "white-space:nowrap;letter-spacing:1px;animation:rain " +
        (12 + Math.random() * 16) + "s linear " + (-Math.random() * 16) + "s infinite;";
      frag.appendChild(span);
    }
    host.appendChild(frag);
  }

  /* ── Reveal on scroll ────────────────────────────────────────────────────── */
  function reveal() {
    var els = Array.prototype.slice.call(document.querySelectorAll("[data-reveal]"));
    function show(e) { e.classList.add("in"); }
    if (!("IntersectionObserver" in window)) { els.forEach(show); return; }
    // Reveal anything already on screen immediately (covers above-the-fold).
    var vh = window.innerHeight || document.documentElement.clientHeight;
    els.forEach(function (e) { var r = e.getBoundingClientRect(); if (r.top < vh * 0.92) show(e); });
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) { show(en.target); io.unobserve(en.target); }
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -8% 0px" });
    els.forEach(function (e) { if (!e.classList.contains("in")) io.observe(e); });
    // Failsafe: never strand content if the observer is throttled (background tab).
    setTimeout(function () { els.forEach(show); }, 1600);
  }

  /* ── Terminal: progressive line reveal (enhancement only) ─────────────────── */
  function terminal() {
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    var term = document.getElementById("scanTerm");
    if (!term) return;
    var lines = Array.prototype.slice.call(term.querySelectorAll(".tl"));
    var started = false;
    function play() {
      if (started) return; started = true;
      lines.forEach(function (ln) { ln.style.opacity = "0"; });
      var i = 0;
      (function step() {
        if (i >= lines.length) return;
        lines[i].style.transition = "opacity .18s ease";
        lines[i].style.opacity = "1";
        var delay = lines[i].dataset.pause ? parseInt(lines[i].dataset.pause, 10) : 95;
        i++; setTimeout(step, delay);
      })();
    }
    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (e) {
        if (e[0].isIntersecting) { play(); io.disconnect(); }
      }, { threshold: 0.3 });
      io.observe(term);
    } else { play(); }
  }

  /* ── Copy buttons ────────────────────────────────────────────────────────── */
  function copies() {
    document.querySelectorAll("[data-copy]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var txt = btn.getAttribute("data-copy");
        if (navigator.clipboard) navigator.clipboard.writeText(txt).catch(function () {});
        var old = btn.textContent;
        btn.textContent = "copied ✓";
        setTimeout(function () { btn.textContent = old; }, 1300);
      });
    });
  }

  /* ── Nav active section ──────────────────────────────────────────────────── */
  function navHighlight() {
    var links = Array.prototype.slice.call(document.querySelectorAll(".nav-links a[href^='#']"));
    var map = {};
    links.forEach(function (a) { var id = a.getAttribute("href").slice(1); var s = document.getElementById(id); if (s) map[id] = a; });
    if (!("IntersectionObserver" in window)) return;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) {
          links.forEach(function (a) { a.classList.remove("active"); });
          if (map[en.target.id]) map[en.target.id].classList.add("active");
        }
      });
    }, { rootMargin: "-45% 0px -50% 0px" });
    Object.keys(map).forEach(function (id) { io.observe(document.getElementById(id)); });
  }

  function init() { binaryRain(); reveal(); terminal(); copies(); navHighlight(); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
