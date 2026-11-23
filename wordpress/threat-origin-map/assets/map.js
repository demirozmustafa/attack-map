/* Threat Origin Map — front end for the [attack_map] shortcode.
   Polls /wp-json/tom/v1/live every 2 s (PHP hosting cannot hold a live stream open) and replays
   each batch's arcs spread over the interval so the map still reads as continuous. */
(function () {
  "use strict";
  const CFG = window.TOM_CFG || {};
  const POLL_MS = 2000, HIDDEN_POLL_MS = 15000;
  let landPromise = null;
  const getLand = () => landPromise || (landPromise = fetch(CFG.land).then(r => r.json()));

  function init(root) {
    const R = n => root.querySelector('[data-r="' + n + '"]');
    const css = getComputedStyle(root);
    const tok = n => css.getPropertyValue(n).trim();
    const TYPES = [
      { k: "brute", name: "Brute force", c: tok("--brute") },
      { k: "web", name: "Web exploit", c: tok("--web") },
      { k: "scan", name: "Port scan", c: tok("--scan") },
      { k: "ddos", name: "DoS / flood", c: tok("--ddos") },
      { k: "c2", name: "Malware / C2", c: tok("--c2") },
    ];
    const TYPE = Object.fromEntries(TYPES.map(t => [t.k, t]));
    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const fmt = d3.format(",");
    const mapC = R("map"), fxC = R("fx"), mctx = mapC.getContext("2d"), fx = fxC.getContext("2d");
    let land = null, proj = null, W = 0, H = 0, dpr = 1, paused = false;
    let site = { name: "", lat: 41.01, lon: 28.98 };
    let nonce = CFG.nonce || "";

    // ---------- map ----------
    function layout() {
      if (!land) return;
      const r = mapC.parentElement.getBoundingClientRect();
      dpr = Math.min(devicePixelRatio || 1, 2); W = Math.max(1, r.width | 0); H = Math.max(1, r.height | 0);
      for (const c of [mapC, fxC]) { c.width = W * dpr; c.height = H * dpr; }
      proj = d3.geoNaturalEarth1().fitExtent([[10, 14], [W - 10, H - 34]], { type: "Sphere" });
      drawBase();
    }
    function drawBase() {
      const off = document.createElement("canvas"); off.width = W; off.height = H;
      const o = off.getContext("2d"); o.beginPath(); d3.geoPath(proj, o)(land); o.fill();
      const px = o.getImageData(0, 0, W, H).data;
      mctx.setTransform(dpr, 0, 0, dpr, 0, 0); mctx.clearRect(0, 0, W, H);
      mctx.strokeStyle = tok("--line"); mctx.lineWidth = .6; mctx.beginPath(); d3.geoPath(proj, mctx)(d3.geoGraticule10()); mctx.stroke();
      const step = W < 500 ? 4 : 5; mctx.fillStyle = tok("--land");
      for (let y = step / 2; y < H; y += step) for (let x = step / 2; x < W; x += step)
        if (px[((y | 0) * W + (x | 0)) * 4 + 3] > 0) { mctx.beginPath(); mctx.arc(x, y, step * .28, 0, 7); mctx.fill(); }
      const [tx, ty] = proj([site.lon, site.lat]);
      mctx.strokeStyle = tok("--target"); mctx.lineWidth = 1.5; mctx.beginPath(); mctx.arc(tx, ty, 6, 0, 7); mctx.stroke();
      mctx.fillStyle = tok("--target"); mctx.beginPath(); mctx.arc(tx, ty, 2.5, 0, 7); mctx.fill();
      mctx.font = '500 11px "IBM Plex Mono",monospace'; mctx.fillText(site.name, tx + 10, ty - 8);
    }

    // ---------- animation ----------
    const arcs = [], rings = [];
    const bez = (p0, p1, c, t) => { const u = 1 - t; return [u * u * p0[0] + 2 * u * t * c[0] + t * t * p1[0], u * u * p0[1] + 2 * u * t * c[1] + t * t * p1[1]]; };
    function addArc(e, ageMs = 0) {
      if (arcs.length > 400 || document.hidden) return;
      arcs.push({ e, c: (TYPE[e.type] || TYPE.scan).c, born: performance.now() - ageMs, dur: 1100 + Math.random() * 900 });
    }
    function frame(now) {
      requestAnimationFrame(frame);
      if (!proj) return;
      fx.setTransform(dpr, 0, 0, dpr, 0, 0); fx.clearRect(0, 0, W, H);
      const tp = proj([site.lon, site.lat]);
      for (let i = arcs.length - 1; i >= 0; i--) {
        const a = arcs[i], sp = proj([a.e.lon, a.e.lat]), age = (now - a.born) / a.dur;
        if (age > 1.9 || !sp) { arcs.splice(i, 1); continue; }
        const d = Math.hypot(tp[0] - sp[0], tp[1] - sp[1]);
        const c = [(sp[0] + tp[0]) / 2, Math.min(sp[1], tp[1]) - d * .35];
        const head = Math.min(age, 1), fade = age > 1 ? 1 - (age - 1) / .9 : 1, tail = reduce ? 0 : Math.max(0, head - .35);
        fx.strokeStyle = a.c; fx.lineWidth = 1.3; fx.lineCap = "round";
        fx.globalAlpha = .18 * fade; fx.beginPath();
        for (let k = 0; k <= 24; k++) { const p = bez(sp, tp, c, head * k / 24); k ? fx.lineTo(p[0], p[1]) : fx.moveTo(p[0], p[1]); } fx.stroke();
        fx.globalAlpha = .95 * fade; fx.beginPath();
        for (let k = 0; k <= 12; k++) { const p = bez(sp, tp, c, tail + (head - tail) * k / 12); k ? fx.lineTo(p[0], p[1]) : fx.moveTo(p[0], p[1]); } fx.stroke();
        if (age < 1) { const h = bez(sp, tp, c, head); fx.globalAlpha = 1; fx.fillStyle = a.c; fx.beginPath(); fx.arc(h[0], h[1], 2.4, 0, 7); fx.fill(); }
        fx.globalAlpha = .7 * fade; fx.fillStyle = a.c; fx.beginPath(); fx.arc(sp[0], sp[1], 2, 0, 7); fx.fill();
        if (age >= 1 && !a.hit) { a.hit = true; rings.push({ c: a.c, born: now }); }
      }
      for (let i = rings.length - 1; i >= 0; i--) {
        const r = rings[i], k = (now - r.born) / 900; if (k > 1) { rings.splice(i, 1); continue; }
        fx.globalAlpha = (1 - k) * .8; fx.strokeStyle = r.c; fx.lineWidth = 1.5; fx.beginPath(); fx.arc(tp[0], tp[1], 4 + k * 22, 0, 7); fx.stroke();
      }
      fx.globalAlpha = 1;
    }

    // ---------- panels (DOM APIs only: log text is attacker-controlled) ----------
    const tb = R("feed");
    function el(tag, props = {}, text) { const n = document.createElement(tag); Object.assign(n, props); if (text != null) n.textContent = text; return n; }
    function addFeedRow(e, fresh = true) {
      const t = TYPE[e.type] || TYPE.scan;
      const tr = el("tr", { className: fresh ? "new" : "" }); tr.style.setProperty("--c", t.c);
      tr.append(el("td", { className: "t" }, new Date(e.ts).toTimeString().slice(0, 8)), el("td", {}, e.ip), el("td", {}, e.cc), el("td", {}, t.k), el("td", {}, e.port ?? "—"));
      const dr = el("tr", { className: "d" }); dr.style.setProperty("--c", t.c);
      const dd = el("td", { colSpan: 5, title: e.detail || "" }, `${e.country} · ${e.detail || e.sensor}`); dd.className = "t"; dr.append(dd);
      tb.prepend(dr); tb.prepend(tr);
      while (tb.rows.length > 80) tb.lastElementChild.remove();
    }
    let settingsUrl = "";
    function renderStats(s) {
      R("kRate").textContent = fmt(s.per_min); R("kTotal").textContent = fmt(s.total_today);
      R("kIps").textContent = fmt(s.unique_ips); R("kCountries").textContent = fmt(s.countries);
      const top = R("top"); top.replaceChildren();
      const max = s.top[0]?.[2] || 1;
      if (!s.top.length) top.append(el("p", { className: "tom-note" }, "No attacks in the last 15 minutes."));
      for (const [cc, name, n] of s.top) {
        const row = el("div", { className: "tom-row" }), nm = el("span", { className: "nm" }, name);
        nm.style.setProperty("--w", (n / max * 100).toFixed(0) + "%");
        row.append(el("span", { className: "cc" }, cc), nm, el("span", { className: "ct" }, fmt(n))); top.append(row);
      }
      const sum = TYPES.reduce((a, t) => a + (s.types[t.k] || 0), 0);
      R("stack").replaceChildren(...TYPES.map(t => { const d = el("div"); d.style.flexGrow = s.types[t.k] || 0; d.style.background = t.c; return d; }));
      R("types").replaceChildren(...TYPES.map(t => {
        const d = el("div"); const i = el("i"); i.style.background = t.c;
        d.append(i, document.createTextNode(t.name), el("em", {}, sum ? Math.round((s.types[t.k] || 0) / sum * 100) + "%" : "–")); return d;
      }));
      R("typeTotal").textContent = fmt(sum) + " events · 15 min";
      R("sampleNote").textContent = [s.demo ? "Demo data" : "", s.sampled ? "High volume · map shows a sample, counts are complete" : ""].filter(Boolean).join(" · ");
      const b = R("banner");
      if (!s.geoip_ready) {
        b.replaceChildren(document.createTextNode("GeoIP database is not installed, so attacks cannot be placed on the map. "));
        if (settingsUrl) b.append(el("a", { href: settingsUrl + "#geoip" }, "Open settings"));
        b.hidden = false;
      } else b.hidden = true;
    }
    R("legend").replaceChildren(...TYPES.map(t => { const s = el("span"); const i = el("i"); i.style.background = t.c; s.append(i, document.createTextNode(t.name)); return s; }));

    let conn = "connecting";
    function setLive(state) {
      conn = state;
      R("live").dataset.s = state;
      R("liveTxt").textContent = paused ? "PAUSED" : { live: "LIVE", down: "RECONNECTING", connecting: "CONNECTING" }[state];
    }
    R("pause").onclick = e => { paused = !paused; e.target.textContent = paused ? "Resume" : "Pause"; setLive(conn); };
    const fullBtn = R("full");
    if (!root.requestFullscreen) fullBtn.hidden = true;
    fullBtn.onclick = () => document.fullscreenElement ? document.exitFullscreen() : root.requestFullscreen().catch(() => {});
    document.addEventListener("fullscreenchange", () => { fullBtn.textContent = document.fullscreenElement === root ? "Exit full screen" : "Full screen"; });

    // ---------- data ----------
    let after = 0, first = true, timer = null, inflight = false;
    async function poll() {
      clearTimeout(timer);
      if (inflight) return;
      inflight = true;
      try {
        const headers = nonce ? { "X-WP-Nonce": nonce } : {};
        const sep = CFG.api.includes("?") ? "&" : "?";
        const res = await fetch(CFG.api + sep + "after=" + after + "&_=" + Date.now(), { headers, credentials: "same-origin", cache: "no-store" });
        if (res.status === 403 && nonce) {
          const j = await res.json().catch(() => ({}));
          if (j.code === "rest_cookie_invalid_nonce") { nonce = ""; inflight = false; return poll(); } // page served from cache with a stale nonce
        }
        if (!res.ok) throw new Error("HTTP " + res.status);
        const d = await res.json();
        if (first || d.site.lat !== site.lat || d.site.lon !== site.lon || d.site.name !== site.name) {
          site = d.site;
          R("eyebrow").textContent = `${site.name} · inbound blocks and IDS alerts`;
          layout();
        }
        if (d.admin && d.settings_url) { settingsUrl = d.settings_url; const a = R("settings"); a.href = settingsUrl; a.hidden = false; }
        renderStats(d.stats);
        const evs = d.events || [];
        if (evs.length) after = evs[evs.length - 1].id;
        if (first) {
          tb.replaceChildren(); evs.forEach(e => addFeedRow(e, false));
          const now = Date.now(); evs.filter(e => now - e.ts < 3000).forEach(e => addArc(e, Math.max(0, now - e.ts - 1000)));
          first = false;
        } else if (!paused) {
          evs.forEach((e, i) => setTimeout(() => { addArc(e); addFeedRow(e); }, evs.length > 1 ? i * POLL_MS / evs.length : 0));
        }
        setLive("live");
      } catch (err) {
        setLive("down");
      }
      inflight = false;
      timer = setTimeout(poll, document.hidden ? HIDDEN_POLL_MS : POLL_MS);
    }
    document.addEventListener("visibilitychange", () => { if (!document.hidden) poll(); });
    new ResizeObserver(() => layout()).observe(mapC.parentElement);

    getLand().then(topo => {
      land = topojson.feature(topo, topo.objects.land);
      layout();
    }).catch(() => {});
    poll();
    requestAnimationFrame(frame);
  }

  function boot() { document.querySelectorAll(".tom-root").forEach(init); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
