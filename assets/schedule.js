(function () {
  // Each row carries the status the BUILD computed (and the ledger state it knew). Here the page improves on that without a rebuild: it reads the published ledger/rounds.json
  // (republishing that one file updates every visitor) and takes "now" from the SERVER's Date header, so a wrong browser clock cannot show a round as open. If either is
  // unavailable it falls back to what the build wrote and then to the browser clock. A round the ledger knows: only `open` can be open, and only until its listed close.
  var rows = document.querySelectorAll("tr[data-opens]");
  var labels = {upcoming: "Opens soon", open: "Open now", closed: "Closed"};
  function apply(now, states) {
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i], opens = Number(r.getAttribute("data-opens")), closes = Number(r.getAttribute("data-closes")), id = r.getAttribute("data-id");
      var ledger = (states && Object.prototype.hasOwnProperty.call(states, id)) ? states[id] : r.getAttribute("data-ledger");
      var st = ledger ? ((ledger === "open" && now <= closes) ? "open" : "closed") : (now < opens ? "upcoming" : (now <= closes ? "open" : "closed"));
      var cell = r.querySelector(".sched-status");
      if (cell) { cell.textContent = labels[st]; }
      var extra = r.querySelectorAll("[data-show]");
      for (var j = 0; j < extra.length; j++) { extra[j].hidden = extra[j].getAttribute("data-show").split(" ").indexOf(st) < 0; }
    }
  }
  apply(Date.now(), null);
  if (!window.fetch) { return; }
  fetch("ledger/rounds.json", {cache: "no-store"}).then(function (resp) {
    var d = Date.parse(resp.headers.get("Date")), now = isNaN(d) ? Date.now() : d;
    if (!resp.ok) { apply(now, null); return; }
    return resp.json().then(function (list) {
      var states = {};
      if (Array.isArray(list)) { list.forEach(function (x) { if (x && x.id) { states[x.id] = x.state; } }); }
      apply(now, states);
    });
  }).catch(function () {});
})();
