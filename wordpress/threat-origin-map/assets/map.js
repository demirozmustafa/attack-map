/* Threat Origin Map — front end for the [attack_map] shortcode.
   Polls /wp-json/tom/v1/live every 2 s (PHP hosting cannot hold a live stream open) and replays
   each batch's arcs spread over the interval so the map still reads as continuous. */
(function () {
  "use strict";
  const CFG = window.TOM_CFG || {};
  const POLL_MS = 2000, HIDDEN_POLL_MS = 15000;
  let landPromise = null;
  const getLand = () => landPromise || (landPromise = fetch(CFG.land).then(r => r.json()));

  async function init(root) {
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
    const mapC=R("map"), fxC=R("fx"), mctx=mapC.getContext("2d"), fx=fxC.getContext("2d");
    const LAND = await getLand();
    const land = topojson.feature(LAND, LAND.objects.land);
    const graticule = d3.geoGraticule10();
    const stage = mapC.parentElement;
    let proj, W=0, H=0, dpr=1, GR=0, paused=false;
    let site = {name:"", lat:41.01, lon:28.98}, sites=[site];   // sites[0] is the main location
    const store = {get:k=>{try{return localStorage.getItem(k)}catch(e){return null}}, set:(k,v)=>{try{localStorage.setItem(k,v)}catch(e){}}};
    let view = store.get("tom-view")==="globe" ? "globe" : "flat";
    const rgba = (hex,a) => {const n=parseInt(hex.replace("#",""),16);return `rgba(${n>>16},${n>>8&255},${n&255},${a})`};
    const RAD = Math.PI/180;
    const vec = (lon,lat) => [Math.cos(lat*RAD)*Math.cos(lon*RAD), Math.cos(lat*RAD)*Math.sin(lon*RAD), Math.sin(lat*RAD)];

    // Land as dots on a lat/lon grid for the globe, sampled from a small equirectangular raster (thinned towards the poles).
    const DOTS = (()=>{
      const step=1.2, w=Math.round(360/step), h=Math.round(180/step);
      const c=document.createElement("canvas"); c.width=w; c.height=h;
      const g=c.getContext("2d",{willReadFrequently:true});
      g.beginPath(); d3.geoPath(d3.geoEquirectangular().fitSize([w,h],{type:"Sphere"}),g)(land); g.fill();
      const px=g.getImageData(0,0,w,h).data, out=[];
      for(let y=0;y<h;y++){
        const lat=90-(y+.5)*step, skip=Math.min(w,Math.max(1,Math.round(1/Math.cos(lat*RAD))));
        for(let x=0;x<w;x+=skip) if(px[(y*w+x)*4+3]>127){const lon=-180+(x+.5)*step; out.push({ll:[lon,lat], v:vec(lon,lat)})}
      }
      return out;
    })();

    // ---------- views ----------
    const spin={drag:0, tilt:0, t0:performance.now()};
    function globeRotation(now){
      const sway = reduce ? 0 : Math.sin((now-spin.t0)/48000*2*Math.PI)*55;  // slow swing around the protected site
      return [-site.lon + sway + spin.drag, Math.max(-60,Math.min(60,-site.lat*.55 + spin.tilt))];
    }
    function centerVec(){const r=proj.rotate(); return vec(-r[0],-r[1])}
    // Screen point, or null when it is on the far side of the globe.
    function P(lon,lat){
      const p=proj([lon,lat]); if(!p||view==="flat") return p;
      const c=centerVec(), v=vec(lon,lat); return v[0]*c[0]+v[1]*c[1]+v[2]*c[2]>0 ? p : null;
    }
    function layout(){
      const r=stage.getBoundingClientRect();
      dpr=Math.min(devicePixelRatio||1,2); W=Math.max(1,r.width|0); H=Math.max(1,r.height|0);
      for(const c of [mapC,fxC]){c.width=W*dpr;c.height=H*dpr}
      stage.dataset.view=view;
      if(view==="flat"){
        proj=d3.geoNaturalEarth1().fitExtent([[10,14],[W-10,H-34]],{type:"Sphere"});
        drawFlatBase();
      } else {
        GR=Math.max(60,Math.min(W*.44,(H-50)*.47));
        proj=d3.geoOrthographic().scale(GR).translate([W/2,(H-30)/2+8]).clipAngle(90).precision(.6).rotate(globeRotation(performance.now()));
      }
    }
    function drawFlatBase(){
      const off=document.createElement("canvas"); off.width=W; off.height=H;
      const o=off.getContext("2d",{willReadFrequently:true}); o.beginPath(); d3.geoPath(proj,o)(land); o.fill();
      const px=o.getImageData(0,0,W,H).data;
      const m=mctx; m.setTransform(dpr,0,0,dpr,0,0); m.clearRect(0,0,W,H);
      m.strokeStyle=rgba(tok("--line"),.8); m.lineWidth=.6; m.beginPath(); d3.geoPath(proj,m)(graticule); m.stroke();
      m.strokeStyle=rgba(tok("--target"),.18); m.lineWidth=1; m.beginPath(); d3.geoPath(proj,m)({type:"Sphere"}); m.stroke();
      const [tx,ty]=proj([site.lon,site.lat]), reach=Math.max(W,H)*.45, step=W<500?4:5;
      const landC=tok("--land"), lit=tok("--target");
      for(let y=step/2;y<H;y+=step)for(let x=step/2;x<W;x+=step){
        if(px[((y|0)*W+(x|0))*4+3]===0) continue;
        const near=Math.max(0,1-Math.hypot(x-tx,y-ty)/reach);           // land brightens towards the protected site
        m.fillStyle=near>.55?lit:landC; m.globalAlpha=near>.55?.18+near*.35:.55+near*.45;
        m.beginPath(); m.arc(x,y,step*.28,0,7); m.fill();
      }
      m.globalAlpha=1;
    }
    function drawGlobeBase(now){
      proj.rotate(globeRotation(now));
      const [cx,cy]=proj.translate(), m=mctx, T=tok("--target");
      m.setTransform(dpr,0,0,dpr,0,0); m.clearRect(0,0,W,H);
      let g=m.createRadialGradient(cx,cy,GR*.92,cx,cy,GR*1.28);                  // atmosphere
      g.addColorStop(0,rgba(T,.30)); g.addColorStop(.35,rgba(T,.10)); g.addColorStop(1,rgba(T,0));
      m.fillStyle=g; m.beginPath(); m.arc(cx,cy,GR*1.28,0,7); m.fill();
      g=m.createRadialGradient(cx-GR*.35,cy-GR*.4,GR*.05,cx,cy,GR*1.02);           // lit ocean
      g.addColorStop(0,"#13213A"); g.addColorStop(.7,"#0B1424"); g.addColorStop(1,"#060B16");
      m.fillStyle=g; m.beginPath(); m.arc(cx,cy,GR,0,7); m.fill();
      m.strokeStyle=rgba(tok("--line"),.55); m.lineWidth=.5; m.beginPath(); d3.geoPath(proj,m)(graticule); m.stroke();
      const c=centerVec(), buckets=[[],[],[],[]], s=Math.max(1.3,GR/150);
      for(const d of DOTS){
        const k=d.v[0]*c[0]+d.v[1]*c[1]+d.v[2]*c[2]; if(k<=.03) continue;
        const p=proj(d.ll); if(p) buckets[Math.min(3,(k*4.2)|0)].push(p);
      }
      m.fillStyle="#5A7BB0";
      buckets.forEach((b,i)=>{m.globalAlpha=.28+i*.22; m.beginPath(); for(const p of b) m.rect(p[0]-s/2,p[1]-s/2,s,s); m.fill()});
      m.globalAlpha=1; m.strokeStyle=rgba(T,.45); m.lineWidth=1.2; m.beginPath(); m.arc(cx,cy,GR,0,7); m.stroke();
    }
    function setView(v){
      view=v; store.set("tom-view",v);
      R("view").textContent = v==="globe" ? "Flat map" : "Globe";
      R("view").setAttribute("aria-pressed", v==="globe");
      arcs.length=0; layout();
    }
    R("view").onclick=()=>setView(view==="globe"?"flat":"globe");
    let drag=null;
    fxC.addEventListener("pointerdown",e=>{if(view!=="globe")return; drag={x:e.clientX,y:e.clientY}; fxC.setPointerCapture(e.pointerId)});
    fxC.addEventListener("pointermove",e=>{
      if(!drag)return;
      spin.drag+=(e.clientX-drag.x)*.35; spin.tilt-=(e.clientY-drag.y)*.35; spin.tilt=Math.max(-50,Math.min(50,spin.tilt));
      drag={x:e.clientX,y:e.clientY};
    });
    fxC.addEventListener("pointerup",()=>{drag=null}); fxC.addEventListener("pointercancel",()=>{drag=null});

    // ---------- animation ----------
    const arcs=[], sparks=[], rings=[], spots=new Map();
    function bez(p0,p1,c,t){const u=1-t;return[u*u*p0[0]+2*u*t*c[0]+t*t*p1[0],u*u*p0[1]+2*u*t*c[1]+t*t*p1[1]]}
    function addArc(e, ageMs=0){
      if(arcs.length>260) return;
      const t=sites[e.loc]||sites[0], c=(TYPE[e.type]||TYPE.scan).c, d=d3.geoDistance([e.lon,e.lat],[t.lon,t.lat]);
      arcs.push({e, t, c, born:performance.now()-ageMs, dur:1200+Math.random()*900,
        geo:d3.geoInterpolate([e.lon,e.lat],[t.lon,t.lat]), alt:.06+.32*d/Math.PI});
      const k=e.cc+Math.round(e.lat/2)+","+Math.round(e.lon/2); let s=spots.get(k);
      if(!s){ if(spots.size>300) return; s={lat:e.lat,lon:e.lon,h:0}; spots.set(k,s) }
      s.h=Math.min(s.h+1,40); s.c=c;
    }
    // Point t∈[0,1] along an arc: a raised Bézier on the flat map, a lifted great circle on the globe.
    function arcPoint(a,t){
      if(view==="flat"){
        const sp=proj([a.e.lon,a.e.lat]), tp=proj([a.t.lon,a.t.lat]); if(!sp||!tp) return null;
        const d=Math.hypot(tp[0]-sp[0],tp[1]-sp[1]); return bez(sp,tp,[(sp[0]+tp[0])/2,Math.min(sp[1],tp[1])-d*.35],t);
      }
      const ll=a.geo(t), p=P(ll[0],ll[1]); if(!p) return null;
      const [cx,cy]=proj.translate(), lift=1+a.alt*Math.sin(Math.PI*t);
      return [cx+(p[0]-cx)*lift, cy+(p[1]-cy)*lift];
    }
    function trace(a,t0,t1,n){
      let open=false; fx.beginPath();
      for(let k=0;k<=n;k++){const p=arcPoint(a,t0+(t1-t0)*k/n); if(!p){open=false;continue} open?fx.lineTo(p[0],p[1]):fx.moveTo(p[0],p[1]); open=true}
      fx.stroke();
    }
    function glow(x,y,c,r,a){
      const g=fx.createRadialGradient(x,y,0,x,y,r); g.addColorStop(0,rgba(c,a)); g.addColorStop(.4,rgba(c,a*.35)); g.addColorStop(1,rgba(c,0));
      fx.fillStyle=g; fx.beginPath(); fx.arc(x,y,r,0,7); fx.fill();
    }
    // Radar at a protected location; extra locations get a smaller one, offset in phase so they don't sweep in sync.
    function drawTarget(t,i,now){
      const tp=P(t.lon,t.lat); if(!tp) return null;
      const [x,y]=tp, T=tok("--target"), k=i?.62:1;
      glow(x,y,T,34*k,.32);
      if(fx.createConicGradient && !reduce){
        const g=fx.createConicGradient(((now/2400+i*.37)%1)*2*Math.PI,x,y);
        g.addColorStop(0,rgba(T,0)); g.addColorStop(.86,rgba(T,0)); g.addColorStop(1,rgba(T,.38));
        fx.fillStyle=g; fx.beginPath(); fx.arc(x,y,44*k,0,7); fx.fill();
      }
      fx.lineWidth=1; fx.strokeStyle=rgba(T,.28);
      for(const r of [16,44]){fx.beginPath(); fx.arc(x,y,r*k,0,7); fx.stroke()}
      if(!reduce){const q=(now/1600+i*.29)%1; fx.strokeStyle=rgba(T,(1-q)*.7); fx.beginPath(); fx.arc(x,y,(6+q*22)*k,0,7); fx.stroke()}
      fx.fillStyle="#E9FCFF"; fx.beginPath(); fx.arc(x,y,2.6,0,7); fx.fill();
      return tp;
    }
    let last=performance.now();
    function frame(now){
      requestAnimationFrame(frame);
      if(!proj) return;
      const dt=Math.min(100,now-last); last=now;
      if(view==="globe") drawGlobeBase(now);
      fx.setTransform(dpr,0,0,dpr,0,0); fx.clearRect(0,0,W,H);
      fx.globalCompositeOperation="lighter"; fx.lineCap="round";
      // heat where attacks come from (fades over ~10 s)
      for(const [k,s] of spots){
        s.h*=Math.exp(-dt/9000); if(s.h<.04){spots.delete(k);continue}
        const p=P(s.lon,s.lat); if(!p) continue;
        glow(p[0],p[1],s.c,6+Math.sqrt(s.h)*6,Math.min(.5,.08+s.h*.035));
      }
      const tps=sites.map((t,i)=>drawTarget(t,i,now));
      for(let i=arcs.length-1;i>=0;i--){
        const a=arcs[i], age=(now-a.born)/a.dur;
        if(age>1.9){arcs.splice(i,1);continue}
        const head=Math.min(age,1), fade=age>1?1-(age-1)/.9:1, tail=reduce?0:Math.max(0,head-.42);
        fx.strokeStyle=a.c;
        fx.globalAlpha=.13*fade; fx.lineWidth=1; trace(a,0,head,30);           // faint full path
        const n=9;                                                              // comet: brighter and thicker towards the head
        for(let k=0;k<n;k++){const q=(k+1)/n; fx.globalAlpha=fade*q*q; fx.lineWidth=.5+q*2; trace(a,tail+(head-tail)*k/n,tail+(head-tail)*(k+1)/n,3)}
        fx.globalAlpha=1;
        const sp=arcPoint(a,0);
        if(sp && age<.7){const k=age/.7; fx.strokeStyle=rgba(a.c,(1-k)*.8); fx.lineWidth=1.2; fx.beginPath(); fx.arc(sp[0],sp[1],2+k*16,0,7); fx.stroke()}
        if(age<1){const h=arcPoint(a,head); if(h){glow(h[0],h[1],a.c,9,.9); fx.fillStyle="#fff"; fx.beginPath(); fx.arc(h[0],h[1],1.4,0,7); fx.fill()}}
        if(age>=1&&!a.hit){
          a.hit=true; const t=a.t; rings.push({t,c:a.c,born:now});
          if(!reduce) for(let j=0;j<7;j++){const ang=Math.random()*7, v=.03+Math.random()*.07; sparks.push({t,c:a.c,born:now,vx:Math.cos(ang)*v,vy:Math.sin(ang)*v})}
        }
      }
      for(let i=rings.length-1;i>=0;i--){
        const r=rings[i], k=(now-r.born)/900, p=P(r.t.lon,r.t.lat); if(k>1){rings.splice(i,1);continue} if(!p) continue;
        fx.globalAlpha=(1-k)*.85; fx.strokeStyle=r.c; fx.lineWidth=1.6; fx.beginPath(); fx.arc(p[0],p[1],4+k*26,0,7); fx.stroke();
      }
      for(let i=sparks.length-1;i>=0;i--){
        const s=sparks[i], t=now-s.born, p=P(s.t.lon,s.t.lat); if(t>650){sparks.splice(i,1);continue} if(!p) continue;
        fx.globalAlpha=1-t/650; fx.fillStyle=s.c; fx.beginPath(); fx.arc(p[0]+s.vx*t,p[1]+s.vy*t,1.3,0,7); fx.fill();
      }
      fx.globalAlpha=1; fx.globalCompositeOperation="source-over";
      fx.font='600 11px "IBM Plex Mono",monospace'; fx.fillStyle="#E9FCFF";
      const placed=[];                                   // nearby locations: slide labels until they no longer overlap
      sites.forEach((t,i)=>{
        const p=tps[i]; if(!p) return;
        const w=fx.measureText(t.name).width;
        for(const [dx,dy] of [[12,-10],[12,18],[-12-w,-10],[-12-w,18],[12,-26],[12,34]]){
          const b=[p[0]+dx,p[1]+dy-10,w,13];
          if(placed.some(q=>b[0]<q[0]+q[2]&&q[0]<b[0]+b[2]&&b[1]<q[1]+q[3]&&q[1]<b[1]+b[3])) continue;
          placed.push(b); fx.fillText(t.name,p[0]+dx,p[1]+dy); return;
        }
      });
    }

    let nonce = CFG.nonce || "";

    // ---------- panels (DOM APIs only: log text is attacker-controlled) ----------
    const tb = R("feed");
    function el(tag, props = {}, text) { const n = document.createElement(tag); Object.assign(n, props); if (text != null) n.textContent = text; return n; }
    function addFeedRow(e, fresh = true) {
      const t = TYPE[e.type] || TYPE.scan;
      const tr = el("tr", { className: fresh ? "new" : "" }); tr.style.setProperty("--c", t.c);
      tr.append(el("td", { className: "t" }, new Date(e.ts).toTimeString().slice(0, 8)), el("td", {}, e.ip), el("td", {}, e.cc), el("td", {}, t.k), el("td", {}, e.port ?? "—"));
      const dr = el("tr", { className: "d" }); dr.style.setProperty("--c", t.c);
      const dd = el("td", { colSpan: 5, title: e.detail || "" }, [e.country, sites.length > 1 ? (sites[e.loc] || sites[0]).name : "", e.sensor, e.detail].filter(Boolean).join(" · ")); dd.className = "t"; dr.append(dd);
      tb.prepend(dr); tb.prepend(tr);
      while (tb.rows.length > 80) tb.lastElementChild.remove();
    }
    let settingsUrl = "";
    function setNum(id, v) {
      const n = R(id), t = fmt(v); if (n.textContent === t) return; const first = n.textContent === "–"; n.textContent = t;
      if (!first && !reduce) { n.classList.remove("bump"); void n.offsetWidth; n.classList.add("bump"); }
    }
    function renderStats(s) {
      setNum("kRate", s.per_min); setNum("kTotal", s.total_today); setNum("kIps", s.unique_ips); setNum("kCountries", s.countries);
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
    let after = 0, first = true, timer = null, inflight = false, sitesKey = "";
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
        const ns = d.sites && d.sites.length ? d.sites : [d.site], key = JSON.stringify(ns);
        if (first || key !== sitesKey) {
          sitesKey = key; sites = ns; site = sites[0];
          R("eyebrow").textContent = `${sites.map(t => t.name).join(" · ")} · inbound blocks and IDS alerts`;
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
    setView(view);
    new ResizeObserver(() => { if (proj) layout(); }).observe(stage);
    poll();
    requestAnimationFrame(frame);
  }

  function boot() { document.querySelectorAll(".tom-root").forEach(r => init(r).catch(() => {})); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
