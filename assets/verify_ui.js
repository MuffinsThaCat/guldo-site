/* verify_ui.js: the page around guldo_verify.js. `renderResult` is a pure function (result -> HTML string) so it can be tested in Node; everything read from a bundle is untrusted, so every value goes through esc().
   The DOM glue at the bottom only runs in a browser. */
(function (root, factory) {
  const ui = factory(root.GuldoVerify || (typeof require === "function" ? require("./guldo_verify.js") : null));
  if (typeof module === "object" && module.exports) module.exports = ui;
  else { root.GuldoVerifyUI = ui; if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", ui.init); }
})(typeof self !== "undefined" ? self : this, function (V) {
  "use strict";

  const esc = (s) => String(s === undefined || s === null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const show = (v) => (v && V && v instanceof V.Num ? v.raw : v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));
  const get = (o, ...path) => { for (const k of path) { if (o === null || o === undefined || typeof o !== "object") return undefined; o = o[k]; } return o; };

  const LABEL = { pass: "PASS", fail: "FAIL", skip: "SKIPPED", info: "INFO" };
  const PILL = { pass: "ok", fail: "bad", skip: "warn", info: "info" };
  const BANNER = { pass: ["ok", "Passed"], partial: ["warn", "Passed in part"], "pinned-by-link": ["warn", "Passed, key from the link"], "pinned-by-site": ["warn", "Passed, key from this page"], unpinned: ["warn", "Not authenticated"], fail: ["bad", "Failed"] };

  /** Keys as a reader types them: one per line or separated by spaces/commas, `# name` comments allowed. Only 64-hex tokens count; anything else is dropped, never guessed at. */
  function parseKeys(text) {
    const out = [];
    for (const raw of String(text || "").split(/\r?\n/)) {
      const line = raw.split("#", 1)[0];
      for (const tok of line.split(/[\s,;]+/)) {
        const t = tok.trim().toLowerCase();
        if (/^[0-9a-f]{64}$/.test(t) && !out.includes(t)) out.push(t);
      }
    }
    return out;
  }

  function certCard(c, pinned) {
    const st = c.st;
    const comp = get(st, "comparison") || {};
    const claims = get(st, "claims");
    const practice = show(get(st, "round", "practice")) === "true";
    const rows = [];
    rows.push(["Round", show(get(st, "round", "id")) + " (" + show(get(st, "round", "domain")) + ")"]);
    rows.push(["Candidate", show(get(st, "candidate", "label")) + (get(st, "candidate", "handle") ? " (" + show(get(st, "candidate", "handle")) + ")" : "")]);
    rows.push(["Baseline", show(get(st, "baseline", "label"))]);
    rows.push(["Solve rate", show(get(comp, "success", "verdict"))]);
    rows.push(["Cost", show(get(comp, "cost", "verdict"))]);
    rows.push(["Signed by key", c.signedBy ? String(c.signedBy) : ""]);
    let claimHtml = "";
    if (Array.isArray(claims) && claims.length) {
      claimHtml = "<ul>" + claims.map((k) => "<li>" + esc(show(get(k, "text"))) + ": <strong>" + (show(get(k, "confirmed")) === "true" ? "confirmed" : "NOT confirmed") + "</strong></li>").join("") + "</ul>";
    }
    const notShown = get(st, "not_shown");
    return '<div class="card vcert"><h3>What this certificate says</h3>' +
      (practice ? '<p class="vwarn"><strong>Practice seed.</strong> Anyone can derive every instance of a practice round, so this shows the method works, not that an agent is good.</p>' : "") +
      '<p class="vstatement">' + esc(show(get(st, "statement"))) + "</p>" +
      '<dl class="vdl">' + rows.map((r) => "<dt>" + esc(r[0]) + "</dt><dd" + (r[0] === "Signed by key" ? ' class="mono"' : "") + ">" + esc(r[1]) + "</dd>").join("") + "</dl>" +
      (claimHtml ? "<h4>Claims it made</h4>" + claimHtml : "") +
      (Array.isArray(notShown) ? '<details><summary>What it does not show</summary><ul>' + notShown.map((n) => "<li>" + esc(show(n)) + "</li>").join("") + "</ul></details>" : "") +
      '<p class="fine">' + (c.pinnedSigner ? "The signing key is one you pinned." : (pinned && pinned.length ? "The signing key is NOT one you pinned." : "You pinned no key, so this shows who signed, not that you trust them.")) + "</p></div>";
  }

  function renderResult(result, opts) {
    opts = opts || {};
    const [cls, word] = BANNER[result.state] || ["bad", "Failed"];
    let h = '<div class="vbanner v-' + esc(cls) + '" role="status"><span class="pill ' + esc(cls) + '">' + esc(word) + "</span><p>" + esc(result.headline) + "</p></div>";
    const n = result.counts;
    h += '<p class="fine">' + esc(n.pass) + " passed, " + esc(n.fail) + " failed, " + esc(n.skip) + " skipped, in your browser, with no upload. This page ran the checks listed below; it does not run the full Python audit (see what it cannot check).</p>";
    h += '<div class="card"><h3>Checks</h3><table class="lb vchecks"><thead><tr><th>Result</th><th>Check</th><th>Detail</th></tr></thead><tbody>' +
      result.checks.map((c) => '<tr><td><span class="pill ' + esc(PILL[c.status] || "idle") + '">' + esc(LABEL[c.status] || c.status) + "</span></td><td>" + esc(c.title) + "</td><td>" + esc(c.detail) + "</td></tr>").join("") + "</tbody></table></div>";
    for (const c of result.certificates || []) h += certCard(c, result.pinned);
    h += '<div class="card"><h3>What this page cannot check</h3><ul>' + (result.notCheckedHere || []).map((x) => "<li><strong>" + esc(x[0]) + ".</strong> " + esc(x[1]) + "</li>").join("") + "</ul></div>";
    if (opts.shareLink) h += '<div class="card"><h3>Link to this check</h3><p class="mono fine" style="word-break:break-all">' + esc(opts.shareLink) + '</p><p class="fine">' + esc(opts.shareNote || "") + "</p></div>";
    return h;
  }

  // ---------------------------------------------------------------- the browser glue (not run in Node)

  function init() {
    const $ = (id) => document.getElementById(id);
    if (!$("v-go")) return;
    const out = $("v-out"), status = $("v-status");
    const say = (t) => { status.textContent = t; };

    async function run(files, o) {
      say("Checking…");
      out.innerHTML = "";
      try {
        const r = await V.verifyBundle(files, o);
        out.innerHTML = renderResult(r, o.share || {});
        say("");
        out.scrollIntoView({ behavior: "smooth", block: "start" });
      } catch (e) {
        out.innerHTML = '<div class="vbanner v-bad" role="alert"><span class="pill bad">Could not check</span><p>' + esc(e && e.message ? e.message : String(e)) + "</p></div>";
        say("");
      }
    }

    const extra = () => ({ partyPins: parseKeys($("v-party") ? $("v-party").value : ""), verifierParty: ($("v-vparty") ? $("v-vparty").value : "").trim() || undefined });
    const tooBig = (n, bytes) => n > 2000 || bytes > (100 << 20);

    async function fromUrl(url, keysText, keySource, more) {
      const base = new URL(url, location.href).href;
      say("Fetching the bundle…");
      let files;
      try { files = await V.loadFromBase(base); } catch (e) {
        out.innerHTML = '<div class="vbanner v-bad" role="alert"><span class="pill bad">Could not fetch</span><p>' + esc(e.message) + " A bundle on another website can only be fetched if that site allows it (CORS); otherwise download the folder and choose it below.</p></div>";
        say("");
        return;
      }
      const keys = parseKeys(keysText);
      const link = location.origin + location.pathname + "?bundle=" + encodeURIComponent(url) + (keys.length ? "&key=" + encodeURIComponent(keys.join(",")) : "");
      await run(files, { ...(more || extra()), pinned: keys, complete: false, keySource: keys.length ? keySource : "none", share: { shareLink: link, shareNote: keys.length ? "Anyone who opens this link repeats the check against the key written in it. A reader should confirm that key against the verifier's own publication, not take it from whoever sent the link." : "No key is in this link, so the check it repeats is not authenticated." } });
    }

    function rootOf(map) {
      const names = Object.keys(map).filter((p) => p === "BUNDLE.json" || p.endsWith("/BUNDLE.json")).sort((a, b) => a.split("/").length - b.split("/").length);
      if (!names.length) return null;
      const prefix = names[0].slice(0, names[0].length - "BUNDLE.json".length);
      const files = Object.create(null);
      for (const p of Object.keys(map)) if (p.startsWith(prefix)) files[p.slice(prefix.length)] = map[p];
      return files;
    }

    async function fromFileList(list) {
      say("Reading the folder…");
      const map = Object.create(null);
      let bytes = 0;
      if (tooBig(list.length, 0)) { out.innerHTML = '<div class="vbanner v-bad" role="alert"><span class="pill bad">Too large</span><p>That folder has more than 2000 files; this page will not read it. Use the Python audit.</p></div>'; say(""); return; }
      for (const f of list) {
        bytes += f.size;
        if (tooBig(0, bytes)) { out.innerHTML = '<div class="vbanner v-bad" role="alert"><span class="pill bad">Too large</span><p>That folder is larger than 100 MB; this page will not read it. Use the Python audit.</p></div>'; say(""); return; }
        const rel = f.webkitRelativePath || f.name;
        map[rel.split("/").slice(f.webkitRelativePath ? 1 : 0).join("/")] = new Uint8Array(await f.arrayBuffer());
      }
      const files = rootOf(map);
      if (!files) { out.innerHTML = '<div class="vbanner v-bad" role="alert"><span class="pill bad">Not a bundle</span><p>No BUNDLE.json was found in what you chose. Choose the bundle folder itself.</p></div>'; say(""); return; }
      await run(files, { ...extra(), pinned: parseKeys($("v-key").value), complete: true, keySource: "you" });
    }

    let droppedBytes = 0, droppedFiles = 0;
    async function readEntry(entry, prefix, map) {
      if (entry.isFile) {
        await new Promise((res, rej) => entry.file(async (f) => {
          droppedFiles++; droppedBytes += f.size;
          if (tooBig(droppedFiles, droppedBytes)) { rej(new Error("that folder is larger than this page will read (2000 files or 100 MB): use the Python audit")); return; }
          map[prefix + entry.name] = new Uint8Array(await f.arrayBuffer()); res();
        }, rej));
      } else if (entry.isDirectory) {
        const reader = entry.createReader();
        for (;;) {
          const batch = await new Promise((res, rej) => reader.readEntries(res, rej));
          if (!batch.length) break;
          for (const e of batch) await readEntry(e, prefix + entry.name + "/", map);
        }
      }
    }

    $("v-go").addEventListener("click", () => { const u = $("v-url").value.trim(); if (u) fromUrl(u, $("v-key").value, "you"); else say("Enter a bundle address, choose a folder, or try the demonstration."); });
    $("v-folder").addEventListener("change", (ev) => { if (ev.target.files.length) fromFileList(Array.from(ev.target.files)); });
    $("v-demo").addEventListener("click", () => {
      const key = $("v-demo").getAttribute("data-key");
      const vparty = $("v-demo").getAttribute("data-vparty") || "";
      $("v-url").value = $("v-demo").getAttribute("data-bundle");
      $("v-key").value = key;
      if ($("v-vparty")) $("v-vparty").value = vparty;
      fromUrl($("v-demo").getAttribute("data-bundle"), key, "site", { partyPins: [], verifierParty: vparty || undefined });
    });
    const drop = $("v-drop");
    drop.addEventListener("dragover", (ev) => { ev.preventDefault(); drop.classList.add("over"); });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", async (ev) => {
      ev.preventDefault(); drop.classList.remove("over");
      const items = Array.from(ev.dataTransfer.items || []).map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
      if (!items.length) { say("Drop the bundle folder (or use the folder button)."); return; }
      say("Reading the folder…");
      const map = Object.create(null);
      droppedBytes = 0; droppedFiles = 0;
      try { for (const e of items) await readEntry(e, "", map); } catch (err) {
        out.innerHTML = '<div class="vbanner v-bad" role="alert"><span class="pill bad">Could not read the folder</span><p>' + esc(err && err.message ? err.message : String(err)) + "</p></div>"; say(""); return;
      }
      const files = rootOf(map);
      if (!files) { out.innerHTML = '<div class="vbanner v-bad" role="alert"><span class="pill bad">Not a bundle</span><p>No BUNDLE.json was found in what you dropped.</p></div>'; say(""); return; }
      await run(files, { ...extra(), pinned: parseKeys($("v-key").value), complete: true, keySource: "you" });
    });

    const q = new URLSearchParams(location.search);
    if (q.get("bundle")) {
      if (q.get("key")) $("v-key").value = q.get("key").split(",").join("\n");
      $("v-url").value = q.get("bundle");
      fromUrl(q.get("bundle"), q.get("key") ? q.get("key").split(",").join("\n") : "", "link");
    }
  }

  return { renderResult, parseKeys, esc, init };
});
