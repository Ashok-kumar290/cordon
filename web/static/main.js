/* Cordon playground client.
 *
 * Three responsibilities:
 *   1. Hydrate the comparative-benchmark table from /api/benchmark.
 *   2. Populate the example dropdown from /api/examples.
 *   3. Submit the action form to /api/check and render the verdict.
 *
 * No frameworks: this is a single landing page; vanilla JS keeps the
 * surface small and the page fast. Tailwind classes are toggled
 * imperatively for verdict styling.
 */

(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  // ─── Element refs ─────────────────────────────────────────────────
  const els = {
    benchmarkRows: $("benchmark-rows"),
    exampleSelect: $("example-select"),
    profileSelect: $("profile-select"),
    kindSelect:    $("kind-select"),
    commandInput:  $("command-input"),
    changesInput:  $("changes-input"),
    checkBtn:      $("check-btn"),
    rateMsg:       $("rate-msg"),

    verdictEmpty:   $("verdict-empty"),
    verdictContent: $("verdict-content"),
    verdictBanner:  $("verdict-banner"),
    verdictReason:  $("verdict-reason"),
    verdictProbes:  $("verdict-probes"),
    verdictScore:   $("verdict-score"),
    verdictProfile: $("verdict-profile"),
    verdictLatency: $("verdict-latency"),
    verdictElapsed: $("verdict-elapsed"),
  };

  // ─── Comparative benchmark table ──────────────────────────────────

  const fmt3 = (n) => Number(n).toFixed(3);
  const fmtMs = (n) => {
    if (n == null) return "—";
    if (n < 1) return `${(n * 1000).toFixed(0)} µs`;
    if (n < 1000) return `${n.toFixed(1)} ms`;
    return `${(n / 1000).toFixed(2)} s`;
  };

  async function loadBenchmark() {
    try {
      const res = await fetch("/api/benchmark");
      const data = await res.json();
      const rows = (data.comparators || [])
        .map((c) => {
          const cls = c.highlight
            ? "bg-accent/5 border-l-2 border-accent"
            : "";
          return `
            <tr class="${cls}">
              <td class="px-4 py-3 ${c.highlight ? "text-accent font-semibold" : ""}">${escapeHTML(c.name)}</td>
              <td class="px-4 py-3 text-right mono">${fmt3(c.tpr)}</td>
              <td class="px-4 py-3 text-right mono">${fmt3(c.fpr)}</td>
              <td class="px-4 py-3 text-right mono ${c.highlight ? "text-accent" : ""}">${fmt3(c.control)}</td>
              <td class="px-4 py-3 text-right mono text-slate-400">${escapeHTML(c.passed)}</td>
              <td class="px-4 py-3 text-right mono text-slate-400">${fmtMs(c.mean_ms)}</td>
            </tr>`;
        })
        .join("");
      els.benchmarkRows.innerHTML =
        rows ||
        `<tr><td colspan="6" class="px-4 py-6 text-center text-slate-500 mono">no data</td></tr>`;
    } catch (e) {
      els.benchmarkRows.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-danger mono">failed to load benchmark</td></tr>`;
    }
  }

  // ─── Examples dropdown ────────────────────────────────────────────

  let EXAMPLES = [];

  async function loadExamples() {
    try {
      const res = await fetch("/api/examples");
      const data = await res.json();
      EXAMPLES = data.examples || [];
      for (const ex of EXAMPLES) {
        const opt = document.createElement("option");
        opt.value = ex.id;
        const tag = ex.expected === "block" ? "🚫" : "✅";
        opt.textContent = `${tag}  ${ex.label}`;
        els.exampleSelect.appendChild(opt);
      }
    } catch (e) {
      // non-fatal: user can still hand-build an action.
    }
  }

  els.exampleSelect.addEventListener("change", () => {
    const ex = EXAMPLES.find((e) => e.id === els.exampleSelect.value);
    if (!ex) return;
    els.kindSelect.value = ex.kind || "shell";
    els.commandInput.value = ex.command || "";
    els.changesInput.value = serializeChanges(ex.changes);
    clearVerdict();
  });

  // ─── Changes serialization ────────────────────────────────────────
  //
  // The textarea uses a tiny "path then ::: then body" format so users
  // can paste multi-file diffs without us shipping a JSON editor:
  //
  //     requirements.txt
  //     :::
  //     reqeusts==2.31.0
  //     ---
  //     README.md
  //     :::
  //     # hi

  function serializeChanges(changes) {
    if (!changes) return "";
    return Object.entries(changes)
      .map(([path, body]) => `${path}\n:::\n${body}`)
      .join("\n---\n");
  }

  function parseChanges(raw) {
    const text = (raw || "").trim();
    if (!text) return null;
    const out = {};
    const blocks = text.split(/^---$/m);
    for (const block of blocks) {
      const idx = block.indexOf("\n:::\n");
      if (idx === -1) continue;
      const path = block.slice(0, idx).trim();
      const body = block.slice(idx + 5);
      if (path) out[path] = body;
    }
    return Object.keys(out).length ? out : null;
  }

  // ─── /api/check submission ────────────────────────────────────────

  els.checkBtn.addEventListener("click", submitCheck);

  async function submitCheck() {
    const payload = {
      kind: els.kindSelect.value,
      command: els.commandInput.value || null,
      changes: parseChanges(els.changesInput.value),
      profile: els.profileSelect.value,
    };

    setLoading(true);
    try {
      const res = await fetch("/api/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (res.status === 429) {
        const data = await res.json().catch(() => ({}));
        renderError(data.detail || "Rate limit exceeded.");
        return;
      }
      if (!res.ok) {
        renderError(`Server returned ${res.status}.`);
        return;
      }

      const verdict = await res.json();
      renderVerdict(verdict);
    } catch (e) {
      renderError("Network error — is the server reachable?");
    } finally {
      setLoading(false);
    }
  }

  function setLoading(loading) {
    els.checkBtn.disabled = loading;
    els.checkBtn.textContent = loading ? "Checking…" : "Check action";
    els.checkBtn.classList.toggle("opacity-60", loading);
  }

  // ─── Verdict rendering ────────────────────────────────────────────

  function clearVerdict() {
    els.verdictEmpty.classList.remove("hidden");
    els.verdictContent.classList.add("hidden");
    els.verdictElapsed.textContent = "";
  }

  function renderError(msg) {
    els.verdictEmpty.classList.add("hidden");
    els.verdictContent.classList.remove("hidden");
    els.verdictContent.classList.add("verdict-enter");
    els.verdictBanner.className =
      "rounded-md p-4 border border-danger/40 bg-danger/10 text-danger";
    els.verdictBanner.innerHTML = `<div class="font-semibold">Error</div><div class="text-sm mt-1 text-slate-300">${escapeHTML(
      msg
    )}</div>`;
    els.verdictReason.textContent = "—";
    els.verdictProbes.innerHTML =
      `<li class="text-slate-500">No probes evaluated.</li>`;
    els.verdictScore.textContent = "—";
    els.verdictProfile.textContent = "—";
    els.verdictLatency.textContent = "—";
  }

  function renderVerdict(v) {
    els.verdictEmpty.classList.add("hidden");
    els.verdictContent.classList.remove("hidden");
    els.verdictContent.classList.remove("verdict-enter");
    void els.verdictContent.offsetWidth; // restart animation
    els.verdictContent.classList.add("verdict-enter");

    const blocked = !!v.blocked;
    const banner = blocked
      ? {
          cls: "border-danger/40 bg-danger/10 text-danger",
          title: "BLOCK",
          sub: "This action would be refused before execution.",
        }
      : {
          cls: "border-accent/40 bg-accent/10 text-accent",
          title: "ALLOW",
          sub: "No probes triggered above threshold.",
        };

    els.verdictBanner.className = `rounded-md p-4 border ${banner.cls}`;
    els.verdictBanner.innerHTML = `
      <div class="flex items-center gap-3">
        <span class="mono text-xl font-bold">${banner.title}</span>
        <span class="text-xs uppercase tracking-wider text-slate-400">
          decision: ${escapeHTML(v.decision)}
        </span>
      </div>
      <div class="text-sm mt-1 text-slate-300">${banner.sub}</div>`;

    els.verdictReason.textContent = v.top_reason || "—";

    const probes = v.probes_triggered || [];
    if (probes.length === 0) {
      els.verdictProbes.innerHTML = `<li class="text-slate-500">No probes triggered.</li>`;
    } else {
      els.verdictProbes.innerHTML = probes
        .map((p) => {
          const sev = severityClass(p.severity);
          return `
            <li class="bg-ink-800/60 border border-ink-700 rounded p-3">
              <div class="flex items-center justify-between gap-3">
                <span class="mono text-sm">${escapeHTML(p.probe)}</span>
                <span class="text-xs mono uppercase ${sev}">${escapeHTML(p.severity)}</span>
              </div>
              <div class="text-xs text-slate-400 mt-1">${escapeHTML(p.evidence)}</div>
              <div class="text-xs text-slate-500 mt-1 mono">score: ${fmt3(p.suspicion_score)}</div>
            </li>`;
        })
        .join("");
    }

    els.verdictScore.textContent = fmt3(v.suspicion_score);
    els.verdictProfile.textContent = v.profile;
    els.verdictLatency.textContent = `${fmtMs(v.elapsed_ms)}`;
    els.verdictElapsed.textContent = `${fmtMs(v.elapsed_ms)}`;
  }

  function severityClass(sev) {
    switch ((sev || "").toLowerCase()) {
      case "critical": return "text-danger";
      case "high":     return "text-danger";
      case "medium":   return "text-warn";
      case "low":      return "text-slate-400";
      default:         return "text-slate-400";
    }
  }

  // ─── Utilities ────────────────────────────────────────────────────

  function escapeHTML(s) {
    return String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  // ─── Boot ─────────────────────────────────────────────────────────

  loadBenchmark();
  loadExamples();
})();
