# 002 — Scope: what this tool answers, and what it refuses to

Supersedes the scope sections of [001](001-access-atlas.md). 001 described a capable
tool; it did not say **which question it exists to answer**, and everything ambiguous
downstream came from that. This document fixes the question first.

## Why 001 was not enough

Three defects, each found by building against a real deployment rather than by review:

**It named no primary moment of use.** Audit (observe, report) and convergence (declare,
enforce) want opposite things — an auditor's first duty is to say "I don't know", a
converger's premise is that the declaration is complete. Building both at once produced
a tool that would revoke a subject's PostgreSQL grants because its S3 grants were
declared. The fix (`managed_systems`) arrived after the damage was visible in a plan.

**Its success criteria measured construction, not use.** "The matrix renders" was met by
a page with 760 columns and 1.26 MB of markup that nobody could read. "Findings are
reported" was met by 2,110 findings, of which 2 mattered. A criterion that a feature
exists cannot fail the way the feature actually fails.

**It left the adapter set open without pricing the openness.** "PostgreSQL, ClickHouse,
S3, extensible" produced three adapters at three different depths — one that walks every
database, one that reads a single flat grant table, one that models two auth planes.
A question answered for one system was unanswerable for another, and nothing said that
was acceptable.

## The question

> **Someone or something reached a resource it should not have. Who else can, and how?**

Incident response is the primary moment. A second, less frequent moment: *before* handing
out access, see exactly what would change.

Everything below follows from those two. Where a feature serves neither, it is cut.

## What this tool refuses to answer

**"Who did it."** This tool reads *current capability*. Whether a specific principal
actually performed an action lives in each system's own audit trail (database query logs,
object-storage access logs), which is a different product with different retention,
volume, and privacy properties. Conflating the two would mean either a shallow log
collector or a permission model nobody trusts.

The tool answers *"who could have"*, which is the question that scopes an investigation.
It must say this out loud rather than let a reader assume otherwise.

**"Is this configuration safe."** Judging a permission set requires knowing the data,
the team, and the obligations. The tool surfaces structure and drift; it does not grade.

**"Apply this change."** See F5.

## Functional requirements

### F1 — Look a subject or resource up, and get the route with the answer

The primary interaction is a lookup, not a browse. Given a subject, return everything it
can reach; given a resource, return everything that can reach it. **Effective privilege
and the path that grants it are one answer, not two screens.**

"alice can read the archive bucket" without "…because a role she holds is a member of a
gating role that a server-held credential is bound to" is not actionable: it names the
symptom and hides the hinge.

*Success:* for a subject whose access is entirely indirect (no grant names them and the
resource together), a single lookup shows both the reachable resource and each hop that
gets there, without the reader issuing a second query.

### F2 — Say "unknown" whenever it is unknown

An unreachable system, a database that refuses connection, an endpoint that returns 403
— none of these mean "no access". The tool must distinguish three states everywhere it
shows access: **granted**, **not granted**, **not checked**.

An adapter failure must not abort the run; it degrades that system to unknown and reports
why. Credential/endpoint mismatch deserves a named hint: a credential from another
environment authenticates nowhere and surfaces as a misleading 403, not as "unknown user".

*Success:* with one system's credential deliberately wrong, the tool completes, reports
that system as unknown with the cause, and plans nothing inside it. No stack trace
reaches the operator.

### F3 — Group at the level a person reasons at

Resources carry a kind (`db:`, `role:`, `table:`, `bucket:`); storage resources carry a
prefix path. The default view groups by kind and by storage container, with the count of
collapsed members visible and the members reachable on demand.

*Success:* on a deployment with 700+ distinct resources, the default view fits a laptop
screen without horizontal scrolling beyond one axis, and every collapsed group states how
many members it holds. A cell covering several resources shows the **strongest**
privilege among them, never the first one found.

### F4 — Keep a snapshot of every observation

Every run writes what it observed. "When did this start" is almost always the second
question in an incident, and a tool that cannot answer it sends the investigator to
somewhere else at the worst moment.

Snapshots are written automatically on every run — no scheduler, no extra command. The
interval is therefore irregular, and the tool must present it honestly ("compared with
your last run, 3 days ago") rather than implying a regular cadence.

Storage: one file per snapshot, line-delimited JSON, beside the configuration and outside
any repository — snapshots name real hosts and principals. Retention by **count**, not
age: a time-based rule silently empties the history of anyone who steps away.

*Success:* two runs bracketing a permission change produce a diff naming that change,
its subject, its resource, and both timestamps. Deleting the snapshot directory degrades
the tool to its stateless behaviour with a notice, never an error.

*Deferred:* a `snapshot` subcommand for cron-driven regularity, same format, so history
taken either way is comparable.

### F5 — Emit commands; do not run them

The tool never writes to a managed system. It renders the native commands that would
converge observed state on declared intent, and stops.

This is a scope decision, not a limitation to apologise for:

- A tool that only reads needs only read credentials. It can then be run by anyone,
  anywhere, during an incident, without being itself a risk.
- Every target system already enforces permissions and already has a change path with its
  own review. Adding a second write path adds a second thing to trust.
- "This tool issues GRANT against your database" is an adoption barrier for a tool whose
  value is that you can point it at production and learn something.

Because the operator runs the output, **the output is the product**: commands must be
copy-pasteable, correctly ordered, and accompanied by the command that undoes them.

*Success:* the emitted block, pasted into the system's own client in the order given,
converges the state; the accompanying inverse block returns it. Neither requires editing.

### F6 — Report drift between declaration and observation, without over-claiming

Where a declaration exists, compare it and report both directions. Where it does not,
say so — silence in a declaration is not an instruction to remove anything.

A revoke needs a mandate for the *system*, not merely for the subject. Declaring one
system's grants for a person says nothing about another system where that person's
access is managed elsewhere.

*Success:* an intent describing one system, for subjects that also hold access in a second
system, emits no command touching the second system, and says why.

### F7 — Name cross-system hops that no grant table records

Some authority leaves a system entirely: a database extension reaching object storage
with a credential the *server* holds, not the caller's. No permission table anywhere
records that hop, so it cannot be discovered — it is declared.

Declared hops participate in path-finding exactly like observed ones, and are marked as
declared so a reader knows the difference between "we saw this" and "we were told this".

*Success:* a principal whose only relevant grant is membership in a gating role appears,
in a lookup, as reaching the storage scope on the far side of the bridge.

## Non-functional

**N1 — Read-only by construction.** No configuration field accepts a credential with
write capability. There is nothing to misuse.

**N2 — No runtime dependency the target environment must accept.** Standard library
first; a database driver may be optional. No service, no daemon, no external
visualisation library — a rendered page must work where scripts from other origins are
blocked.

**N3 — Failure is per-system.** One unreachable system degrades that system, never the
run.

**N4 — Verification travels the path the user travels.** A check performed over a channel
that skips authentication (a local socket configured to trust) proves nothing about the
credential. Where the tool documents how to verify, it names the channel.

**N5 — No secret is written anywhere the tool controls.** Snapshots record principals,
resources, and privileges — never credentials. Configuration references credentials by
environment variable, never by value.

## Phases

**Phase 1 — the question, answered.** F1, F2, F3, F5, F6, F7. Lookup-first interface;
matrix demoted to an overview. Remove the write path, its credentials, and its audit log.

**Phase 2 — memory.** F4. Snapshots on every run; diff against the previous one; "since
when" answerable.

**Phase 3 — regularity and reach.** `snapshot` subcommand for cron. Deeper adapters where
a question is currently unanswerable for one system but answerable for another. Login-path
probes (N4 as a feature rather than a documented practice).

## What this changes in the existing implementation

Removed: the apply path, admin credential configuration, and the write audit log.

Demoted: the matrix, from primary interface to overview. It stays — comparing several
subjects side by side is genuinely useful — but it is no longer the first screen.

Promoted: paths. Previously a separate page; now part of every answer.

Kept, and now with a stated reason: resource grouping (F3), unknown-vs-absent (F2),
per-system mandate (F6), declared bridges (F7). Each of these was added after a real
deployment exposed its absence. This document exists so the next four are found here
instead.
