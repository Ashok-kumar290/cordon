/* Cordon Cloud dashboard client.
 *
 * Polls /v1/metrics and /v1/events every 2 s, diffs against the last
 * snapshot, prepends new rows with an enter animation, and renders the
 * sparkline. Vanilla JS — no framework — to keep the dashboard fast
 * and self-contained.
 */

(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  const REFRESH_MS = 2000;
  const SEVERITY_COLOR = {
    critical:  "text-red-400 border-red-500/30 bg-red-500/10",
    dangerous: "text-orange-300 border-orange-500/30 bg-orange-500/10",
    high:      "text-yellow-300 border-yellow-500/30 bg-yellow-500/10",
    medium:    "text-sky-300 border-sky-500/30 bg-sky-500/10",
    low:       "text-neutral-300 border-white/10 bg-white/5",
  };

  // The access token is read once from the URL the operator opened
  // the dashboard with (``/?t=<token>``) and forwarded on every API
  // call. We never persist it anywhere — that way revoking access is
  // just "rotate the env var on the Space"; no client-side state to
  // chase.
  const ACCESS_TOKEN = new URLSearchParams(location.search).get("t") || "";

  const state = {
    project: "demo",
    window:  86400,
    decision: "",
    seenIds: new Set(),
    lastTopId: 0,
    polling: true,
  };

  /** Build ``/v1/<path>`` with the dashboard access token appended. */
  function apiUrl(path, params = {}) {
    const u = new URL(path, location.origin);
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== "") {
        u.searchParams.set(k, v);
      }
    }
    if (ACCESS_TOKEN) u.searchParams.set("t", ACCESS_TOKEN);
    return u.pathname + u.search;
  }

  // ─── Filters ──────────────────────────────────────────────────
  for (const btn of document.querySelectorAll(".flt")) {
    btn.classList.add("border", "border-white/10", "text-neutral-300", "hover:text-white",
                      "hover:border-white/30", "transition-colors");
    btn.addEventListener("click", () => {
      for (const b of document.querySelectorAll(".flt")) {
        b.classList.remove("active", "bg-white", "text-black", "border-white");
        b.classList.add("text-neutral-300", "border-white/10");
      }
      btn.classList.add("active", "bg-white", "text-black", "border-white");
      btn.classList.remove("text-neutral-300", "border-white/10");
      state.decision = btn.dataset.value || "";
      state.seenIds = new Set();   // re-render from scratch
      $("events-body").innerHTML = "";
      poll();
    });
  }
  // initial styling for "all"
  document.querySelector('.flt[data-value=""]').classList.add(
    "bg-white", "text-black", "border-white",
  );

  $("window-select").addEventListener("change", (e) => {
    state.window = Number(e.target.value);
    poll();
  });

  // ─── Endpoint snippet auto-detection ──────────────────────────
  // Show the same origin the dashboard is being served from, so users
  // who self-host see the right URL in the snippet.
  $("endpoint-snippet").textContent = `"${location.origin}"`;

  // ─── Polling ──────────────────────────────────────────────────
  async function poll() {
    if (!state.polling) return;
    try {
      const [metricsRes, eventsRes] = await Promise.all([
        fetch(apiUrl("/v1/metrics", {
          project: state.project,
          window_s: state.window,
        })),
        fetch(apiUrl("/v1/events", {
          project: state.project,
          limit: 100,
          decision: state.decision || undefined,
        })),
      ]);
      if (metricsRes.status === 401 || eventsRes.status === 401) {
        $("live-status").textContent = "access denied";
        state.polling = false;
        // The page itself will already have shown the access-required
        // gate from the server if the user landed here without a token,
        // but this guards against tokens being rotated mid-session.
        return;
      }
      const metrics = await metricsRes.json();
      const events  = await eventsRes.json();
      renderMetrics(metrics);
      renderEvents(events.events || []);
      renderSparkline(metrics.sparkline || []);
      $("live-status").textContent = `live · ${new Date().toLocaleTimeString()}`;
    } catch (err) {
      $("live-status").textContent = "offline (retrying)";
    }
  }

  function renderMetrics(m) {
    $("m-total").textContent = m.n_total.toLocaleString();
    $("m-total-sub").textContent =
      `${humanWindow(m.window_s)} · ${m.n_allowed} allowed`;

    const rate = (m.block_rate * 100).toFixed(1);
    const el = $("m-block");
    el.textContent = `${rate}%`;
    el.className = "mt-2 mono text-3xl " +
      (m.block_rate >= 0.3 ? "text-red-400" :
       m.block_rate >= 0.1 ? "text-orange-300" : "text-white");
    $("m-block-sub").textContent =
      `${m.n_blocked} blocked · ${m.n_flagged} flagged`;

    $("m-score").textContent = (m.mean_score ?? 0).toFixed(3);

    const top = (m.top_probes || [])[0];
    if (top) {
      $("m-top-probe").textContent = top.probe;
      $("m-top-probe-sub").textContent = `${top.count} hits`;
    } else {
      $("m-top-probe").textContent = "—";
      $("m-top-probe-sub").textContent = "no probes fired";
    }
  }

  function renderEvents(events) {
    const tbody = $("events-body");
    const empty = $("events-empty");

    if (!events.length) {
      tbody.innerHTML = "";
      empty.classList.remove("hidden");
      return;
    }
    empty.classList.add("hidden");

    // Build full HTML for known events, prepend rows we haven't seen.
    // The most recent events come first from /v1/events (ts DESC).
    const newRows = [];
    for (const ev of events) {
      if (state.seenIds.has(ev.id)) continue;
      state.seenIds.add(ev.id);
      newRows.push(rowHTML(ev, /* fresh = */ state.lastTopId > 0));
    }

    if (newRows.length) {
      // Prepend new rows in time order (oldest first → newest at top).
      tbody.insertAdjacentHTML("afterbegin", newRows.join(""));
      // Trim to 100 rows so the DOM stays light.
      while (tbody.children.length > 100) {
        tbody.removeChild(tbody.lastChild);
      }
      // Wire row click handlers for the freshly-inserted rows.
      for (const row of tbody.querySelectorAll("tr[data-event-id]:not([data-bound])")) {
        row.setAttribute("data-bound", "1");
        row.addEventListener("click", () => openDetail(Number(row.dataset.eventId)));
      }
    }

    state.lastTopId = events[0].id;
  }

  function rowHTML(ev, fresh) {
    const sev = (ev.top_severity || "low").toLowerCase();
    const sevCls = SEVERITY_COLOR[sev] || SEVERITY_COLOR.low;
    const decisionCls =
      ev.decision === "block" ? "text-red-400" :
      ev.decision === "flag"  ? "text-yellow-300" :
                                "text-green-400";
    const cmd = ev.command_preview || (ev.kind === "write_file" ? "(file diff)" : "");
    const evidence = ev.top_evidence || cmd || "—";
    const score = ev.suspicion_score != null
      ? ev.suspicion_score.toFixed(3)
      : "—";
    return `
      <tr data-event-id="${ev.id}"
          class="cursor-pointer hover:bg-white/5 transition-colors ${fresh ? "row-enter" : ""}">
        <td class="px-5 py-3 text-neutral-400 mono text-xs whitespace-nowrap">
          ${relTime(ev.ts)}
        </td>
        <td class="px-3 py-3 text-neutral-300 mono text-xs">${escapeHTML(ev.kind || "—")}</td>
        <td class="px-3 py-3 mono text-xs uppercase ${decisionCls}">${escapeHTML(ev.decision)}</td>
        <td class="px-3 py-3">
          ${ev.top_probe
            ? `<span class="mono text-xs px-2 py-0.5 rounded border ${sevCls}">${escapeHTML(ev.top_probe)}</span>`
            : `<span class="text-neutral-600 mono text-xs">—</span>`}
        </td>
        <td class="px-3 py-3 text-neutral-300 text-xs max-w-[460px] truncate" title="${escapeHTML(evidence)}">
          ${escapeHTML(evidence)}
        </td>
        <td class="px-5 py-3 text-right mono text-xs text-neutral-300">${score}</td>
      </tr>`;
  }

  // ─── Sparkline ────────────────────────────────────────────────
  function renderSparkline(buckets) {
    // buckets[0] = most recent; we want to draw left → right oldest → newest.
    const data = buckets.slice().reverse();
    const W = 600, H = 80, pad = 4;
    const n = data.length;
    if (!n) return;
    const max = Math.max(1, ...data.map(b => b.n || 0));
    const xs = i => pad + (i * (W - 2 * pad)) / Math.max(1, n - 1);
    const ys = v => H - pad - (v / max) * (H - 2 * pad);

    const linePts = data.map((b, i) => `${xs(i).toFixed(1)},${ys(b.n || 0).toFixed(1)}`).join(" ");
    const blockedPts = data.map((b, i) =>
      `${xs(i).toFixed(1)},${ys(b.n_blocked || 0).toFixed(1)}`
    ).join(" ");
    const areaPts =
      `${pad},${H - pad} ${linePts} ${(W - pad).toFixed(1)},${H - pad}`;

    $("sparkline").innerHTML = `
      <polygon points="${areaPts}"
               fill="rgba(255,255,255,0.04)" stroke="none"/>
      <polyline points="${linePts}"  fill="none"
                stroke="rgba(255,255,255,0.55)" stroke-width="1.5"/>
      <polyline points="${blockedPts}" fill="none"
                stroke="rgba(239,68,68,0.85)" stroke-width="1.5"/>
    `;
  }

  // ─── Detail drawer ────────────────────────────────────────────
  async function openDetail(eventId) {
    const drawer   = $("detail-drawer");
    const backdrop = $("detail-backdrop");
    const body     = $("detail-body");
    body.innerHTML = `<div class="text-neutral-500 mono text-xs">loading…</div>`;
    drawer.classList.remove("hidden");
    backdrop.classList.remove("hidden");
    try {
      const r = await fetch(apiUrl(`/v1/events/${eventId}`, {
        project: state.project,
      }));
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const ev = await r.json();
      body.innerHTML = detailHTML(ev);
    } catch (err) {
      body.innerHTML = `<div class="text-red-400 mono text-xs">${escapeHTML(err.message)}</div>`;
    }
  }

  function detailHTML(ev) {
    const probes = (ev.raw && ev.raw.probes_triggered) || [];
    return `
      <div class="space-y-4">
        <div>
          <div class="text-[11px] uppercase tracking-wider text-neutral-500">action</div>
          <div class="mt-1 mono text-sm text-white">${escapeHTML(ev.action_id || "—")}</div>
          <div class="mt-1 mono text-xs text-neutral-500">
            ${escapeHTML(ev.kind || "—")} · ${new Date(ev.ts * 1000).toISOString()}
          </div>
        </div>
        <div>
          <div class="text-[11px] uppercase tracking-wider text-neutral-500">decision</div>
          <div class="mt-1 flex items-baseline gap-3">
            <span class="mono text-lg uppercase ${
              ev.decision === "block" ? "text-red-400"
              : ev.decision === "flag" ? "text-yellow-300" : "text-green-400"
            }">${escapeHTML(ev.decision)}</span>
            <span class="mono text-sm text-neutral-400">
              score ${ev.suspicion_score != null ? ev.suspicion_score.toFixed(3) : "—"}
            </span>
          </div>
        </div>
        ${ev.command_preview ? `
          <div>
            <div class="text-[11px] uppercase tracking-wider text-neutral-500">command preview</div>
            <pre class="mt-1 mono text-xs bg-black/40 border border-white/5 rounded p-3
                        whitespace-pre-wrap break-words">${escapeHTML(ev.command_preview)}</pre>
          </div>` : ""}
        <div>
          <div class="text-[11px] uppercase tracking-wider text-neutral-500">probes triggered</div>
          ${probes.length ? `
            <div class="mt-1 space-y-2">
              ${probes.map(p => `
                <div class="border border-white/5 rounded p-3">
                  <div class="flex items-center gap-2">
                    <span class="mono text-xs px-2 py-0.5 rounded border ${
                      SEVERITY_COLOR[(p.severity||"low").toLowerCase()] || SEVERITY_COLOR.low
                    }">${escapeHTML(p.probe)}</span>
                    <span class="mono text-xs text-neutral-400">${escapeHTML(p.severity || "—")}</span>
                    <span class="mono text-xs text-neutral-500 ml-auto">
                      conf ${(p.confidence ?? 0).toFixed(3)}
                    </span>
                  </div>
                  <div class="mt-2 text-xs text-neutral-300">
                    ${escapeHTML(p.evidence || "—")}
                  </div>
                </div>
              `).join("")}
            </div>` : `<div class="mt-1 text-neutral-500 mono text-xs">none</div>`}
        </div>
        <details class="border border-white/5 rounded p-3">
          <summary class="cursor-pointer text-[11px] uppercase tracking-wider text-neutral-500">
            raw payload
          </summary>
          <pre class="mt-2 mono text-[11px] text-neutral-400 overflow-auto scrollbar
                      whitespace-pre-wrap break-all">${escapeHTML(JSON.stringify(ev.raw, null, 2))}</pre>
        </details>
      </div>`;
  }

  $("detail-close").addEventListener("click", closeDetail);
  $("detail-backdrop").addEventListener("click", closeDetail);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDetail(); });
  function closeDetail() {
    $("detail-drawer").classList.add("hidden");
    $("detail-backdrop").classList.add("hidden");
  }

  // ─── Utilities ────────────────────────────────────────────────
  function escapeHTML(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function relTime(ts) {
    const d = Date.now() / 1000 - ts;
    if (d < 60)        return `${Math.max(0, Math.floor(d))}s ago`;
    if (d < 3600)      return `${Math.floor(d / 60)}m ago`;
    if (d < 86400)     return `${Math.floor(d / 3600)}h ago`;
    return `${Math.floor(d / 86400)}d ago`;
  }
  function humanWindow(s) {
    if (s >= 86400)   return `last ${Math.round(s / 86400)} d`;
    if (s >= 3600)    return `last ${Math.round(s / 3600)} h`;
    if (s >= 60)      return `last ${Math.round(s / 60)} min`;
    return `last ${Math.round(s)} s`;
  }

  // ─── Kick off ─────────────────────────────────────────────────
  poll();
  setInterval(poll, REFRESH_MS);
})();
