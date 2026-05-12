# Runtime sandboxing — Layer 3 of the Cordon defense stack

Cordon is **the action firewall for AI agents** — it catches an
agent's proposed action *before* that action runs. There's a
complementary class
of attack — described in §3.6 of [`threat-model.md`](threat-model.md)
— that Cordon explicitly does not catch: an action whose harm is only
realised when *something else* later executes the file it produced.
Concatenating a benign and a malicious file into `report.pdf`, writing
a Python script that runs cleanly when invoked but contains an
`os.system` call several layers down, dropping an executable into a
directory another process scans — all of these slip past every
content-aware probe because the *action* Cordon sees is structurally
safe.

The right answer to that class is **runtime sandboxing**: confining the
process that *executes* what the agent produced, so even if a hostile
payload reaches execution, it can't reach the rest of the system.

This document is what you point a design partner at when they ask
*"OK, but what about runtime?"* It's intentionally vendor-honest:
Cordon doesn't sell a sandbox, and the sandbox vendors we recommend
don't sell a pre-execution gate. The two layers compose; neither
replaces the other.

---

## 1. The decision tree

Pick one of these based on what your agent *runs*, not what it
*generates*:

| If your agent executes... | Use |
|---|---|
| Arbitrary shell commands inside a long-lived container | **gVisor** (Google) — drop-in OCI replacement for runc with a userspace kernel |
| Untrusted code (especially Python / Node) in short-lived workloads | **Firecracker** (AWS / open-source) — microVM, 125 ms cold-start |
| Serverless / per-request agents | **Cloudflare Workers** or **Vercel Edge Functions** — each invocation is already isolated |
| Local-dev or CI-only and you want zero new infra | **Docker** with `--read-only --network none --cap-drop ALL --user 65534:65534` and a tmpfs `/tmp` |
| Browser-facing code (e.g. an agent that runs HTML/JS) | **WebContainer (StackBlitz)** or **iframe-with-sandbox-attribute** |
| You have $0 budget and can't add infra | **Bubblewrap** (`bwrap`, the same sandbox Flatpak uses) on Linux |

Three principles regardless of vendor:

1. **No network by default.** Most agent payloads need no network to
   work; allowing it is the single biggest attack surface.
2. **No persistent state by default.** Mount `/tmp` as tmpfs, mount
   everything else read-only, and reset the container between actions.
3. **Drop all capabilities you don't need.** Linux: `--cap-drop=ALL`,
   then add back specifically (`--cap-add=NET_BIND_SERVICE` if you need
   to bind ports below 1024, almost never useful for agents).

---

## 2. gVisor — drop-in for runc

[github.com/google/gvisor](https://github.com/google/gvisor)

gVisor implements a userspace kernel that intercepts system calls
before they reach the host kernel. From Docker's perspective it's
just another OCI runtime — `--runtime=runsc` — but every syscall the
container makes is filtered through ~30 lines of safe Go instead of
millions of lines of Linux C. CVE blast-radius drops accordingly.

**When to use:** You already have a Kubernetes / Docker workflow and
want stronger isolation per pod / container without rewriting orchestration.

**Cordon integration:**

```bash
# Run a container whose entrypoint is whatever the agent generated,
# behind gVisor. Cordon already gated the agent's call; gVisor gates
# the resulting code's syscalls.

docker run --rm \
    --runtime=runsc \
    --read-only --tmpfs /tmp --network none \
    --cap-drop ALL --user 65534:65534 \
    cordon-runner:latest \
    /workdir/agent-output.sh
```

**Limits:** Some syscalls aren't implemented (rare in normal agent
workloads; you'll find them if you do high-performance I/O).

---

## 3. Firecracker — microVM-grade isolation

[firecracker-microvm.github.io](https://firecracker-microvm.github.io/)

Firecracker is the microVM AWS Lambda runs on. Each agent invocation
gets its own kernel (not just its own namespace) with ~125 ms startup,
~5 MB memory overhead. The trust boundary is the same as between two
EC2 instances on the same host.

**When to use:** Per-request agents, multi-tenant agent platforms, or
anything where the threat model includes hostile *agents* (not just
hostile inputs).

**Cordon integration:** Firecracker is normally used via an
orchestrator like Fly Machines, Koyeb, or AWS Lambda (Lambda uses
Firecracker under the hood). You don't typically invoke `firecracker`
directly. The integration is:

```
Cordon (pre-execution) → Approved action → Fly Machines / Lambda
        ↓                                          ↓
   verdict, telemetry                       Firecracker microVM
                                            (one per invocation)
```

**Limits:** Cold-start is real (125 ms minimum). Not the right
answer for high-throughput, latency-sensitive agents.

---

## 4. Cloudflare Workers / Vercel Edge

[workers.cloudflare.com](https://workers.cloudflare.com/) ·
[vercel.com/edge](https://vercel.com/edge)

Each request runs in its own V8 isolate with no filesystem, no
syscalls, and a 50 ms CPU budget on the free tier. The trust boundary
is enforced by V8's same-origin model — battle-tested across every
web page on Earth.

**When to use:** Agents whose tools are HTTP fetches and arithmetic.
Probably 70 % of "AI agents" people are building today.

**Cordon integration:** Run the Cordon SDK inside the Worker on every
tool call:

```js
import { Guard } from '@cordon/wasm'   // WASM build of cordon-ai

addEventListener('fetch', async (event) => {
    const action = parseAgentToolCall(await event.request.json())
    const verdict = Guard.strict().check(action)
    if (verdict.decision === 'block') {
        return new Response(verdict.explanation, { status: 403 })
    }
    return await executeAction(action)
})
```

(Note: as of v0.2.3 we don't ship `@cordon/wasm` yet. Run the SDK
in a Python Worker / Node Worker for now.)

**Limits:** No long-running tasks. No persistent filesystem. If your
agent needs to keep state between invocations, you need durable
objects or an external store.

---

## 5. Docker with hardened flags — the budget option

```bash
docker run --rm \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    --network none \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 100 \
    --memory 256m --cpus 0.5 \
    --user 65534:65534 \
    cordon-runner:latest \
    /workdir/agent-output.sh
```

This is the "I just need *something*" sandbox. It's not as strong as
gVisor or Firecracker — a kernel exploit (rare but real) escapes both
namespaces and capabilities — but it's free, works on any Docker host,
and stops 95 % of the attack vectors a Cordon-allowed-but-trojaned
script could exploit.

**The seven flags above are the entire shopping list.** Drop any one
of them and you've meaningfully widened the attack surface. The
`--security-opt no-new-privileges` and `--user 65534:65534` (nobody)
flags in particular are non-obvious; they prevent privilege escalation
even if the inner process has a setuid bug.

---

## 6. Bubblewrap — Linux-native, no container daemon

[github.com/containers/bubblewrap](https://github.com/containers/bubblewrap)

`bwrap` is the sandbox Flatpak uses. It builds a namespace-based
sandbox from scratch in ~5 ms — much faster than spinning up a
Docker container. Useful when you want to sandbox individual commands
inside an already-trusted host process.

```bash
bwrap \
    --ro-bind / / \
    --proc /proc --dev /dev \
    --tmpfs /tmp \
    --unshare-all \
    --die-with-parent \
    -- bash /workdir/agent-output.sh
```

**When to use:** Local development agents on Linux, CI runners, or
inside another container where you want a second nested boundary.

**Limits:** Linux-only. The syntax is unforgiving. You'll iterate
on the bind list more than you'd like.

---

## 7. What about WebAssembly?

[Wasmtime](https://wasmtime.dev/) and [Wasmer](https://wasmer.io/)
both offer "run untrusted code with deny-by-default capabilities" as
their pitch. They're the right answer when:

* Your agent generates *programs*, not shell commands (compile-to-WASM
  workflow).
* You want the same sandbox to run identically on macOS / Linux /
  Windows / browser.
* You're willing to constrain what your agent can use to the WASI
  surface (no native syscalls; no `subprocess`; carefully-curated
  file/network capabilities).

**WASM is not the answer for the generic "agent runs shell commands"
case** because shell commands need a full Unix syscall surface and
WASI's syscall coverage is partial. WASM is fantastic when you control
the language; it's wrong when you don't.

---

## 8. The thing nobody warns you about

Whatever sandbox you pick, **the egress filter is the single most
important configuration**. A sandboxed process that can `curl
attacker.com` has 80 % of the attack surface of an unsandboxed one,
because the agent's secrets and your customer data exfiltrate through
that egress regardless of whether the process can write to `/etc`.

* gVisor: default-deny egress + an allowlist (`--network=host` is
  always wrong; use a bridge network with explicit egress rules).
* Firecracker: per-microVM tap interface; firewall it at the host.
* Docker: `--network none` if you can; otherwise a custom bridge with
  iptables egress allowlist.
* Cloudflare Workers: configure outbound rules via
  `wrangler.toml` → `[[services]]`.

If you only do one thing on top of pre-execution gating, do this.

---

## 9. The handoff sentence

When a design partner asks *"OK, so you don't catch the
`cat benign.txt malicious.bin > report.pdf` class — what do?"*, the
answer that closes the deal is:

> *"You pair Cordon with a runtime sandbox at the execution layer.
> We're not religious about which sandbox; the four we see customers
> succeed with most often are gVisor, Firecracker, Cloudflare Workers,
> and hardened Docker. We've documented exact configurations for each
> at [`docs/runtime-sandboxing.md`](runtime-sandboxing.md). The
> two-layer design — Cordon stops the actions, the sandbox contains
> the payloads — is what gives you actual defense in depth. Nobody
> who ships only one of these gives you both."*

That's it. The sandbox conversation should take exactly as long as it
takes to read that paragraph aloud.

---

*Last reviewed: 2026-05-12 · matches `cordon-ai==0.2.3`.*
