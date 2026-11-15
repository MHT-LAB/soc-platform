// The overview pages' only script: tick the UTC clock in the header. It starts from the
// server's time and counts forward, so a wrong clock on this device changes nothing.
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
