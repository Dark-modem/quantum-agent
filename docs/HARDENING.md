# HARDENING — declarative security profiles with safe-apply + rollback

Owner: phase1/hardening session. Module: `quantum-agent/internal/hardening`
(this repo, branch `phase1/hardening`). Installers: `install-agent.sh`,
`install-panel.sh` (repo root). This document is the module's public
contract: what the panel can push today, what the safe-apply guarantees,
and the PROPOSED protocol v2 message shapes the contract session can wire
into `quantum-protocol` (nothing in `quantum-protocol` was edited).

## 1. What the module is

Security + network-optimization basics as **declarative profiles** (data,
not bash): ufw policy and allow/limit rules, additive sshd hardening, a
safe-hygiene sysctl drop-in, fail2ban jail, time sync, persistent journald.
Every item implements **Detect → Plan (diff) → Apply → Verify → Revert**,
and every apply records a journal whose undo is machine-executable.

The module deliberately does NOT do performance tuning (BBR, buffers,
conntrack sizing, NIC registers) — that is the netopt engine's job
(`internal/agent` netopt profiles, `netopt.*` commands). The two systems
co-exist by ownership: hardening refuses keys the netopt drop-in owns, and
vice versa is documented in netopt.

## 2. Profile (the JSON document the panel pushes)

```jsonc
{
  "version": 1,                      // ProfileVersion; mismatch → refused
  "name": "conservative",            // 1-64 safe chars
  "firewall": {
    "default_deny_incoming": true,   // null/omitted = leave as-is
    "allow_outgoing": true,
    "allows": [ {"port": 443, "proto": "tcp", "from": "", "owner": "service:decoy"} ],
    "limits":  [ {"port": 22,  "proto": "tcp", "owner": "service:ssh"} ]  // ufw limit
  },
  "ssh": {
    "port": 0,                       // 0 = unchanged; N adds a listener on N
    "key_only": null,                // true only allowed when a key is verified present
    "permit_root": "",               // "no" | "prohibit-password" | "yes" | ""
    "max_auth_tries": 0,             // 0 = leave, else 1-10
    "fail2ban": {"enabled": true, "maxretry": 5, "findtime_sec": 600, "bantime_sec": 3600}
  },
  "sysctl": [ {"key": "net.ipv4.tcp_syncookies", "value": "1"} ],
  "timesync": {"ensure_active": true},
  "logging": {"persistent_journal": true}
}
```

Built-in: `hardening.Conservative(sshPort, extraOpens)` — what the
installers apply on day one. It never moves the SSH port and never enables
key-only.

Guarantees enforced at plan time (violations become BLOCKED items, shown to
the operator with the reason, never silently dropped):

- **Key-only is never enforced blind.** With no authorized public key for
  any user → blocked. With root as the only key holder and
  `permit_root: "no"` → blocked.
- **A deny-incoming flip is refused while no rule covers the current/new
  SSH port.** (Rule adds are always planned first, so a profile that
  declares the SSH port is fine.)
- **ufw is never reset/enabled/disabled/flushed.** If ufw is inactive,
  all firewall items are blocked with instructions (enabling is the
  operator's gated decision; `install-agent.sh --enable-firewall` is the
  day-one opt-in with the SSH door verified first).
- **Foreign files are never overwritten.** The module owns exactly four
  drop-ins + one sysctl file; anything else at those paths → refused.
- **netopt-owned sysctl keys are delegated** (blocked with a pointer to the
  netopt profile), never fought over.

## 3. SAFE-APPLY (the lockout contract)

Any plan with a risky item (SSH config, firewall policy, rule removal)
refuses to apply without safe-apply. The safe-apply sequence, in order:

1. **Pre-open**: additive ufw allows (never rate-limited) for BOTH the
   current SSH port(s) and the new one, tagged `quantum:hardening:safe-apply`.
2. **Verify the CURRENT path**: real `SSH-` banner dialed on
   127.0.0.1:<port>. Already broken → abort, nothing modified.
3. **Arm the timer**: the journal's undo is rendered into a self-contained
   POSIX-sh script (`/var/lib/quantum-agent/hardening/rollback-<id>.sh`)
   and armed with `systemd-run --on-active=<t>s --unit=quantum-harden-<id>
   --collect /bin/sh <script>`, default and minimum **120 s**. Arming
   failure aborts before any risky change.
4. **Mutate**: sshd drop-in written → `sshd -t` gate → `systemctl reload`
   (NEVER restart) → banner re-probe; firewall rule adds; policies with an
   immediate banner re-probe after each deny flip; rule removals last.
5. **Handoff**: the panel must **Confirm** (disarm + finalize) or the timer
   fires and the script restores the previous drop-ins (embedded bytes),
   policies, rules and sysctls — even if the agent binary is dead or being
   upgraded, because the script depends only on `sh` + systemd.

Simulated-failure proof: `TestSafeApplySimulatedFailureRollsBack` (unit,
hermetic) — new port refuses banners after reload → apply fails → journal
renamed `.rolledback`, drop-in removed, pre-open rules deleted, timer
disarmed, sshd reloaded back. UNVERIFIED on real hardware: the netns
integration test (§7) exercises the script executor, not real ufw/sshd.

After confirmation, pre-open allows for ports that stopped listening are
removed; ones for still-listening, undeclared ports are KEPT (safe side)
and reported in `status.leftovers`.

## 4. Go API (for the contract session to wire)

```go
package hardening // github.com/Dark-modem/quantum-agent/internal/hardening

Dispatch(ctx, hardening.Request{Op: "detect|plan|apply|status|confirm|rollback",
    Profile: "<json>", SafeApply: *bool, RollbackTimeoutSec: int,
    JournalID: string}) *Result
// Result{Ok, Error, State, Plan, Journal, Armed, TimerUnit, Verify, Leftovers}

Detect(ctx) *DetectedState
PlanProfile(profile Profile, state *DetectedState) (*Plan, error)
ApplyProfile(ctx, profile Profile, opts ApplyOpts) (*ApplyResult, error)
Confirm(ctx, journalID string) (*Journal, error)   // "" = latest
Rollback(ctx, journalID string) (*Journal, error)
```

All types are JSON-serializable end to end. `ApplyOpts.SafeApply` defaults
true and is REFUSED (errUnsafeApply) when false and the plan is risky.

## 5. PROPOSED protocol v2 message shapes (do not implement from this doc
   without re-review; the protocol repo is contract-owned)

Protocol v1 already carries desired state (`desired`/`ack`, monotonic
revision) and allowlisted commands (`command`/`result`, `MutatingOps`
require `payload.confirm == "yes"`). Hardening slots into both, additively:

**a. Desired state (preferred path).** The panel pushes a `desired`
envelope whose payload gains a hardening section; the agent applies it
through the module and acks with the journal reference:

```jsonc
// ctrl -> agent: desired (payload)
{
  "revision": 42,
  "hardening": { ...Profile as in §2... },
  "hardening_timeout_sec": 120          // optional, >= 120
}
// agent -> ctrl: ack (payload)
{
  "revision": 42,
  "kind": "hardening",
  "ok": true,
  "journal_id": "hp_1699999999_ab12cd34",
  "armed": true, "timer_unit": "quantum-harden-hp_1699999999_ab12cd34",
  "plan": { ...Plan... }               // so the panel UI can show the diff
}
```

**b. Commands (imperative path), allowlist additions:**

| Command | payload | result |
|---|---|---|
| `hardening.detect` | `{}` | `Result{State}` |
| `hardening.plan` | `{"profile": {...}}` | `Result{Plan}` |
| `hardening.apply` (MutatingOps) | `{"profile": {...}, "safe_apply": true, "rollback_timeout_sec": 120}` | `Result{Journal, Armed, TimerUnit, Verify}` |
| `hardening.confirm` (MutatingOps) | `{"journal_id": "..."}` | `Result{Journal, Leftovers}` |
| `hardening.rollback` (MutatingOps) | `{"journal_id": ""}` | `Result{Journal}` |
| `hardening.status` | `{}` | `Result{Journal?, Armed, State}` |

Semantics for the panel UI: `apply` returns ARMED, not done — the UI must
show a 120 s confirm banner ("keep new state / rollback now"); no confirm ⇒
automatic rollback. `MutatingOps` gating (`confirm == "yes"`) stays as in v1;
the module's own safe-apply is a second, independent gate.

**c. Capability string**: agent hello adds `CapHardening = "hardening"`
only when the module is wired; the panel must not push hardening desired
state to agents without it (old agents reject unknown desired sections the
same way they tolerate unknown command names).

## 6. Installers

- `install-agent.sh` — flags: `--server --token|--token-file --name --role
  --version --binary --checksum --ssh-port --open PORT[/proto] (repeatable)
  --enable-firewall --with-fail2ban --no-start --check --yes`. Additive
  tagged firewall allows (`quantum:installer:ssh|declared`), SSH banner
  verified before/after any firewall action, conservative sysctl drop-in
  with per-key read-back, journald+timesync, conservative Profile JSON
  written to `/etc/quantum-agent/desired/hardening-profile.json`.
- `install-panel.sh` — flags: `--port --base-path --username
  --password|--password-file|--generate-password --version --binary
  --checksum --no-start --check`. Dedicated non-login user +
  `ProtectSystem=strict` sandbox (the panel is management-only), credential
  never printed by the installer, additive tagged panel-port allow.
- Unit-hardening exceptions are documented in the script headers (agent:
  no ProtectSystem/ProtectKernelTunables because it writes /etc drop-ins,
  /proc/sys and self-updates; ProtectHome=read-only for SSH-forward key
  material. Panel: CAP_NET_BIND_SERVICE only for ports < 1024.)

## 7. Tests and verification status

- Hermetic unit tests (fake host, call-order assertions): 20 passing with
  `-race` on Linux (WSL Ubuntu 24.04, Go 1.23.4): plan guards, safe-apply
  ordering, timer-arm failure abort, simulated-failure rollback, confirm
  and file-restore rollback, foreign-file refusal, convergence.
- `tests/hardening_lab.sh` (Linux, root, unshare netns): executes a real
  generated rollback script against a fake sshd listener + real sysctl
  keys. **RUN 2026-11-04 (WSL Ubuntu 24.04, inside netns): 7/7 PASS.**
  Skips cleanly when unshare/root is unavailable.
- NOT yet verified (UNVERIFIED): a real ufw/sshd safe-apply round on a
  disposable VM. Before production use, run once on a scratch server per
  the checklist in tests/hardening_lab.sh.

## 8. Files

| Path | Purpose |
|---|---|
| `internal/hardening/hardening.go` | Profile types, validation, Conservative() |
| `internal/hardening/detect.go` | DetectedState (firewall/ssh/sysctl/f2b/time/keys) |
| `internal/hardening/plan.go` | diff → PlanItems incl. blocks/convergence |
| `internal/hardening/apply.go` | apply orchestration, non-risky phase |
| `internal/hardening/safeapply.go` | pre-open → arm timer → risky mutations |
| `internal/hardening/rollback.go` | journal rollback + generated sh script |
| `internal/hardening/sysctlapply.go` | merged owned drop-in + read-back |
| `internal/hardening/verify.go` | banner probe, per-item verify, sshd -t/reload |
| `internal/hardening/journal.go` | journal persistence + terminal states |
| `internal/hardening/api.go` | Dispatch + status/leftovers |
| `install-agent.sh`, `install-panel.sh` | installers (see §6) |
| `tests/hardening_lab.sh` | netns integration (Linux, root, skippable) |
