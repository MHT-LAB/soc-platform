// The overview pages' only script. Two small jobs: tick the UTC clock in the header (from
// the server's time, so a wrong clock on this device changes nothing), and reload the page
// every minute so the numbers stay current.
(function () {
  var el = document.getElementById("utc-clock");
  if (!el) return;
  var start = parseInt(el.getAttribute("data-epoch"), 10) * 1000;
  if (isNaN(start)) return;
  var began = performance.now();
  var days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  var months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function two(n) { return (n < 10 ? "0" : "") + n; }
  function tick() {
    var d = new Date(start + (performance.now() - began));
    el.textContent = days[d.getUTCDay()] + ", " + months[d.getUTCMonth()] + " " + two(d.getUTCDate()) +
      " · UTC " + two(d.getUTCHours()) + ":" + two(d.getUTCMinutes()) + ":" + two(d.getUTCSeconds());
  }
  var local = document.getElementById("local-clock");
  var fmt = null;
  try {
    fmt = new Intl.DateTimeFormat("en-US", {
      timeZone: local && local.getAttribute("data-tz"), hour: "numeric", minute: "2-digit",
      timeZoneName: "short"
    });
  } catch (e) { fmt = null; }
  function tickLocal() {
    if (!local || !fmt) return;
    local.textContent = fmt.format(new Date(start + (performance.now() - began))).replace(/\u202f/g, " ");
  }
  tick();
  tickLocal();
  setInterval(function () { tick(); tickLocal(); }, 1000);
})();

// Refresh: reload the same address (so the period and client filters are kept) once a minute.
// Never while the tab is hidden, and not while the reader is in the middle of something: a
// <details> is open or some text is selected. A tab that comes back to the front after more
// than a minute away reloads straight away.
(function () {
  var EVERY = 60000;
  var last = Date.now();
  function busy() {
    if (document.querySelector("details[open]")) return true;
    var sel = window.getSelection && window.getSelection();
    return !!(sel && String(sel).length > 0);
  }
  function due() {
    if (document.visibilityState !== "visible") return;
    if (busy()) return;
    if (Date.now() - last < EVERY - 1000) return;
    location.reload();
  }
  setInterval(due, EVERY);
  document.addEventListener("visibilitychange", due);
})();
