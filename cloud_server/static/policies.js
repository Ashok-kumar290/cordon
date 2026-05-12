/* Cordon Cloud — Policy editor (Lane 4).
 *
 * Self-contained, no framework. Drives the #policies section of
 * dashboard.html:
 *
 *   - Loads the project's saved policy on mount (GET /v1/policies/{p}).
 *   - Validates as the operator types (debounced POST /v1/policies/validate).
 *   - Save  → PUT /v1/policies/{p}
 *   - Try   → POST /v1/try with the editor's current text inline
 *   - Revert → re-fetch the saved version
 *   - Delete → DELETE /v1/policies/{p} (with a confirm)
 *
 * The dashboard token is read from the URL once (via the same
 * convention as dashboard.js) and forwarded as ``?t=`` on every
 * authed request. We don't rely on cookies — the magic-link flow is
 * the only auth surface and it lives entirely in the URL.
 *
 * Why a separate file: keeps the policy code reviewable on its own,
 * and lets us A/B-deploy the editor without touching the well-tested
 * verdict-stream code path.
 */

(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  // The editor only exists on the dashboard. Bail quietly if loaded
  // somewhere else (defensive: the same script gets bundled in the
  // landing template too, by mistake or by future intent).
  const editor = $("pol-editor");
  if (!editor) return;

  const status   = $("pol-status");
  const meta     = $("pol-meta");
  const btnVal   = $("pol-validate");
  const btnSave  = $("pol-save");
  const btnRev   = $("pol-revert");
  const btnDel   = $("pol-delete");
  const tryKind  = $("pol-try-kind");
  const tryCmd   = $("pol-try-cmd");
  const btnTry   = $("pol-try-run");
  const tryOut   = $("pol-try-result");

  const TOKEN = new URLSearchParams(location.search).get("t") || "";

  /** Build a relative URL with the access token forwarded. */
  function url(path) {
    const u = new URL(path, location.origin);
    if (TOKEN) u.searchParams.set("t", TOKEN);
    return u.pathname + u.search;
  }

  /** Read the project from the dashboard's project-select; falls back to "demo". */
  function project() {
    const sel = document.getElementById("project-select");
    return (sel && sel.value) || "demo";
  }

  // ─── Status line helpers ──────────────────────────────────────────

  function setStatus(msg, kind = "info") {
    const colors = {
      info:    "text-neutral-500",
      ok:      "text-emerald-400",
      warn:    "text-yellow-300",
      error:   "text-red-400",
    };
    status.className =
      "mono text-xs px-5 py-2 border-t border-white/5 min-h-[34px] " +
      (colors[kind] || colors.info);
    status.textContent = msg;
  }

  function setMeta(text) {
    meta.textContent = text || "";
  }

  // ─── Saved-state tracking ─────────────────────────────────────────

  // The last text we know matches the server. Used by Revert + by the
  // dirty-indicator on the Save button.
  let savedText = "";
  let savedVersion = null;

  function applyServerState(payload) {
    savedText = payload.text || "";
    savedVersion = payload.version ?? null;
    editor.value = savedText;
    if (savedVersion != null) {
      const ts = new Date((payload.updated_at || 0) * 1000);
      setMeta(`v${savedVersion} · saved ${ts.toLocaleString()}`);
    } else {
      setMeta("");
    }
    refreshDirty();
  }

  function refreshDirty() {
    const dirty = editor.value !== savedText;
    btnSave.classList.toggle("opacity-50", !dirty);
    btnSave.disabled = !dirty;
    btnRev.classList.toggle("opacity-50", !dirty);
    btnRev.disabled = !dirty;
  }

  // ─── Initial load ─────────────────────────────────────────────────

  async function loadCurrentPolicy() {
    setStatus("loading current policy…");
    try {
      const r = await fetch(url(`/v1/policies/${encodeURIComponent(project())}`));
      if (r.status === 404) {
        applyServerState({ text: "", version: null, updated_at: 0 });
        setStatus("no policy set yet — type one in and click save.", "info");
        return;
      }
      if (!r.ok) {
        setStatus(`load failed: HTTP ${r.status}`, "error");
        return;
      }
      const body = await r.json();
      applyServerState(body);
      setStatus("loaded.", "ok");
    } catch (err) {
      setStatus(`load error: ${err.message}`, "error");
    }
  }

  // ─── Validate (debounced + on-demand) ─────────────────────────────

  let validateTimer = 0;

  async function validateNow({ silent = false } = {}) {
    const text = editor.value;
    if (!text.trim()) {
      if (!silent) setStatus("editor is empty.", "warn");
      return;
    }
    try {
      const r = await fetch(url("/v1/policies/validate"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      const body = await r.json();
      if (body.ok) {
        setStatus(
          `valid — profile: ${body.profile}, ${body.n_rules} rule(s).`,
          "ok",
        );
      } else {
        setStatus(`line ${body.line}: ${body.message}`, "error");
      }
    } catch (err) {
      setStatus(`validate failed: ${err.message}`, "error");
    }
  }

  editor.addEventListener("input", () => {
    refreshDirty();
    clearTimeout(validateTimer);
    // Debounce: 500 ms after the operator stops typing — typing-fast
    // operators get a single round-trip per pause, not per keystroke.
    validateTimer = setTimeout(() => validateNow({ silent: true }), 500);
  });

  btnVal.addEventListener("click", () => validateNow({ silent: false }));

  // ─── Save ─────────────────────────────────────────────────────────

  btnSave.addEventListener("click", async () => {
    const text = editor.value;
    setStatus("saving…");
    try {
      const r = await fetch(url(`/v1/policies/${encodeURIComponent(project())}`), {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      if (r.status === 401) {
        setStatus(
          "401 — open the dashboard via the magic-link URL with `?t=<token>`.",
          "error",
        );
        return;
      }
      if (!r.ok) {
        // The server returns {detail: {message, line, snippet}} for
        // syntax errors. Show the line number so it's actionable.
        const body = await r.json().catch(() => ({}));
        const d = body.detail || {};
        setStatus(
          d.line
            ? `line ${d.line}: ${d.message}`
            : `save failed: HTTP ${r.status}`,
          "error",
        );
        return;
      }
      const body = await r.json();
      applyServerState(body);
      setStatus(`saved as v${body.version}.`, "ok");
    } catch (err) {
      setStatus(`save error: ${err.message}`, "error");
    }
  });

  // ─── Revert ───────────────────────────────────────────────────────

  btnRev.addEventListener("click", () => {
    editor.value = savedText;
    refreshDirty();
    setStatus(savedVersion ? `reverted to v${savedVersion}.` : "reverted.", "info");
  });

  // ─── Delete ───────────────────────────────────────────────────────

  btnDel.addEventListener("click", async () => {
    if (!confirm(`Delete policy for project "${project()}"? Agents will fall back to the strict default.`)) return;
    setStatus("deleting…");
    try {
      const r = await fetch(url(`/v1/policies/${encodeURIComponent(project())}`), {
        method: "DELETE",
      });
      if (!r.ok) {
        setStatus(`delete failed: HTTP ${r.status}`, "error");
        return;
      }
      const body = await r.json();
      applyServerState({ text: "", version: null, updated_at: 0 });
      setStatus(
        body.removed ? "deleted." : "no policy was set; nothing to delete.",
        "info",
      );
    } catch (err) {
      setStatus(`delete error: ${err.message}`, "error");
    }
  });

  // ─── Try this policy ──────────────────────────────────────────────

  function renderTry(body) {
    const decision = (body.decision || "?").toLowerCase();
    const colors = {
      block: "text-red-300 bg-red-500/10 border-red-500/30",
      flag:  "text-yellow-300 bg-yellow-500/10 border-yellow-500/30",
      allow: "text-emerald-300 bg-emerald-500/10 border-emerald-500/30",
    };
    const cls = colors[decision] || "text-neutral-300 border-white/10 bg-white/5";

    const probes = (body.probes || []).map(
      (p) => `<div class="text-neutral-500">→ ${escapeHtml(p.probe)} (${escapeHtml(p.severity)}) · ${escapeHtml(p.evidence || "")}</div>`,
    ).join("");

    const reason = body.reason ? `<div class="text-neutral-400 mt-1">${escapeHtml(body.reason)}</div>` : "";

    tryOut.innerHTML = `
      <div class="px-2 py-1 rounded border ${cls} inline-block uppercase tracking-wider">${decision}</div>
      <div class="text-neutral-500">profile: <span class="text-neutral-300">${escapeHtml(body.profile || "?")}</span></div>
      ${reason}
      ${probes}
    `;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  btnTry.addEventListener("click", async () => {
    const cmd = (tryCmd.value || "").trim();
    if (!cmd) {
      tryOut.innerHTML = '<div class="text-yellow-300">enter a command first.</div>';
      return;
    }
    tryOut.innerHTML = '<div class="text-neutral-500">running probes…</div>';
    try {
      const r = await fetch(url("/v1/try"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          kind: tryKind.value || "shell",
          command: cmd,
          policy: editor.value,
        }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        const d = body.detail || {};
        tryOut.innerHTML =
          `<div class="text-red-300">${
            d.line ? `line ${d.line}: ${escapeHtml(d.message || "")}` : `error: HTTP ${r.status}`
          }</div>`;
        return;
      }
      renderTry(await r.json());
    } catch (err) {
      tryOut.innerHTML =
        `<div class="text-red-300">${escapeHtml(err.message)}</div>`;
    }
  });

  // ─── Boot ────────────────────────────────────────────────────────

  // Reload the saved policy if the operator switches projects via the
  // dashboard's project-select. Same convention dashboard.js uses.
  const projSel = document.getElementById("project-select");
  if (projSel) projSel.addEventListener("change", loadCurrentPolicy);

  loadCurrentPolicy();
})();
