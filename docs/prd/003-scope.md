# 003 — Scope: a steward's console

Supersedes [002](002-scope.md), which was wrong about who this is for.

## What 002 got wrong

002 asked the user *when* they would reach for the tool and offered three answers —
periodic check, incident response, change gate. All three are moments of **reading**.
The user's own description was not about a moment at all:

> "I most of all want to see, per service, what permissions I have granted. It would be
> really good if I could also grant them from here. That was my first wanted use case.
> And since each service's permissions sit at a different level of abstraction, being
> specialised per service would be good. And I'd like to see what permissions each user
> has."

That is a standing management surface with a granting workflow — a fourth option the
question never offered. 002 took the forced choice as the answer and rebuilt the document
around incident response, a story the user never told. In doing so it **demoted the
inventory view to an overview and deleted the granting path outright**.

Two of the three arguments 002 used to delete writing were also unsound:

- *"The target systems already have a change path."* False for one of them. Where IAM is
  a document that must be fetched, edited, and PUT back, this tool **is** the safest
  change path — deleting it hands the operator a hand-edited JSON blob instead.
- *"Read-only means the tool is not itself a risk."* Already achieved by 001's structure:
  read paths never resolve the write credential. That is read-only *by default*, which
  is what matters; 002 escalated it to *by construction* and lost a capability for it.

## Who this is for

**A steward of several data services who granted the access and has to keep answering
for it.** Not an auditor visiting once, not an incident responder arriving after the
fact — the person whose name is on the grants.

Their standing questions, in the order they ask them:

1. What have I granted, per service?
2. What does this person have, across services?
3. Give this person that access. Take it back.
4. Is any of it not what I think it is?

## Non-goals

**"Who used it."** This reads capability, not activity. Whether a principal actually
touched something lives in each system's audit trail — different retention, volume, and
privacy. The tool answers *who can*, and says so plainly rather than letting a reader
assume otherwise.

**"Is this safe."** Judging a permission set needs the data, the team, and the
obligations. The tool shows structure and mismatch; it does not grade.

**Activity-based authorization and a replacement authorization plane.** Enforcement
stays native. Declaration-based convergence is a separate CLI mode; see F5.

## Functional requirements

### F1 — Inventory by service, alongside the map

The map is the front page (`/`). The Services page (`/services`) shows what is granted
per service, without a query, and is directly available in navigation.

Per service, because that is how permissions are actually held — a database role is not a
storage policy, and flattening them into one vocabulary loses the thing the steward needs
to recognise.

*Success:* on a deployment with 700+ distinct resources across 3 services, the Services page
answers "what is granted in service X" for each X **without collapsing a service to a
single number**. Specifically: a reader can name, for one service, which kinds of
resource are granted and to how many subjects, and reach the individual resources from
there in one step. A view that shows `<service> · 712` satisfies neither.

*Known gap (closed 2026-09-03):* "what **I** granted" was not answerable — `Grant`
carried no grantor. `Grant.grantor` now carries it where the source records it
(PostgreSQL: `pg_auth_members.grantor`, aclitem grantor); ClickHouse and the S3 identity
documents record no grantor, so those rows say nothing rather than implying an author.
The subject page shows a *granted by* column when any row has one, and a *Granted by
<subject>* section answers the question from the person's own page.

### F2 — A subject's access is one page, with routes

Given a person or service account, show what they can reach across every service, and
**how** — including hops through roles and across systems.

Effective privilege without its route is not actionable: it names the symptom and hides
the hinge. If access arrives through a role, removing the role is the fix, and the page
must show which role.

*Success:* for a subject whose access is entirely indirect, one page shows the reachable
resource **and every distinct route to it** — not merely one route. A page that shows one
of three paths fails.

### F3 — Grant and revoke, explicitly, from here

The steward names a subject, a resource, and a privilege, and the tool performs it. Both
directions: withholding revoke would be the odd asymmetry, and an explicit revoke is
exactly as bounded as an explicit grant — the operator said what to remove.

Every operation shows the native command it will run before running it, and records what
it ran.

*Success:* granting then revoking the same privilege returns the system to its prior
observed state, byte for byte in the observation. The preview shown beforehand is the
command actually issued — not a paraphrase.

*Bounded by construction:* only the named subject, resource, and privilege are touched.
The tool has no path that removes something the operator did not name. That property is
what makes revoke safe, and F5 exists to keep it true.

### F4 — Per-service depth, with nothing silently dropped

Each service keeps its own vocabulary and its own hazards. The shared model is a **join
key** — enough to line services up beside each other — not a lowest common denominator.

**A fact that does not fit the shared model must surface, never be filtered away.** Three
historical failure modes broke this rule; these remain regression cases, not open
implementation tasks:

- Grants that are global rather than scoped to one container are dropped by a filter that
  requires a container name. The strongest privilege in the system is the one that does
  not appear.
- Explicit deny statements in a storage policy are skipped, so access that is blocked
  renders as allowed.
- One class of database grant is read through a view that only reveals rows involving the
  current role, so a read-only observer sees other people's grants as absent — the exact
  confusion F6 forbids, occurring inside an adapter.

*Success:* for each service, a fact the shared model cannot express (a global grant, a
deny, a scope the observer cannot see) appears in the output as itself — as a finding, an
unknown, or a service-specific field — and never as silence. Adding a service means
extending this list, not widening the shared model.

### F5 — Convergence is a separate, explicitly scoped CLI mode

Comparing a written declaration against observation is useful. Acting on the difference —
removing whatever the declaration omits — is a different and much stronger claim, and it
is the one that nearly deleted grants that were managed elsewhere.

Explicit operations (F3) are the console change path. The CLI also supports
`apply --write`: revokes require both a managed subject and a described system. A system
is described when intent contains a grant for it, or names it in `managed_systems`
(including a deliberately empty system). Writing one grant therefore claims the system
for managed subjects; partial intent must remain report-only. Silence never claims it.

*Success:* no code path removes a grant that the operator did not name, or that a
declaration did not explicitly claim the system for.

### F6 — Granted, not granted, and not checked are three different answers

An unreachable service, a database that refuses connection, an endpoint returning a
permission error — none of these mean "nothing is granted". Every surface that shows
access distinguishes all three.

Failure is scoped as narrowly as the adapter can determine. Demoting an entire service to
unknown because one database refused is a worse answer than demoting that database.

*Success:* with one service's credential deliberately wrong, the tool completes and marks
**only what it could not read** as unknown, with the cause. An implementation that marks
the whole service unknown when a narrower scope was determinable fails. No stack trace
reaches the operator.

### F7 — Cross-system hops are declared, and marked as declared

Some authority leaves a service entirely — a database extension reaching storage with a
credential the *server* holds rather than the caller's. No permission table records that
hop, so it is declared in configuration.

Declared hops take part in route-finding like observed ones and are **visibly marked as
declared**, because "we saw this" and "we were told this" are different confidences.

*Success:* a subject whose only relevant grant is membership in a gating role appears as
reaching the far-side scope, with that hop rendered differently from observed hops.

### F8 — Every run leaves a snapshot

"Since when" is the second question after "who". Each run writes what it observed, one
line-delimited JSON file per run, beside the configuration and outside any repository.

No scheduler. The interval is therefore irregular and the tool says so — "compared with
your previous run, 3 days ago" — rather than implying a cadence it does not have.

*Success:* two runs bracketing a change produce a diff naming that change, its subject,
its resource, and both timestamps, **and containing nothing that did not change**. A diff
that names the change among hundreds of spurious entries fails.

## Non-functional

**N1 — Read paths never resolve a write credential.** Reading and writing take separate
configuration; nothing that only reads can reach the credential that writes.

**N2 — Preview before every write, always.** No flag disables it.

**N3 — Emitted commands must be executable in the service they name.** A block that
cannot be pasted into that system's own client is not a command, it is prose. Where a
service has no such client, the tool performs the operation itself rather than describing
it.

**N4 — No runtime dependency the target environment must accept.** Standard library
first; a driver may be optional. No daemon, no external visualisation library — a
rendered page must work where scripts from other origins are blocked.

**N5 — Comparison respects subsumption.** A broader privilege satisfies a narrower one.
Set difference over strings reports a grant as missing when a wider grant already covers
it, which turns the front page into noise.

**N6 — Observation records contain no credentials.** Snapshots record principals,
resources, privileges and unread scopes. Configuration references environment variables.
An explicitly configured credential file must be private. Approval bearer tokens are the
one deliberate stored secret: the approval directory is mode 700 and files mode 600;
requester output excludes them. See `SECURITY.md`.

## Phases

**Phase 1 — the console.** F1, F2, F4, F6, F7 and N5. Inventory front page, subject page
with routes, per-service depth with nothing dropped. Fix the three silent drops before
anything is built on top of them.

**Phase 2 — the verb.** F3, N2, N3. Explicit grant and revoke. Add grantor to the model
so F1's known gap closes.

**Phase 3 — memory and comparison.** F8, then declaration comparison as a report. F5 is a separate CLI operation, with its subject/system mandate checked before revokes.

## Originally cut from scope

- **Naming-drift linting.** It serves none of the four standing questions.
- **A separate route page.** Routes belong inside F2's answer; a second page is the same
  content at a worse moment.
- **Undo blocks alongside emitted commands.** Doubles the output surface; nothing in the
  user's account asks for it. F3's revoke covers the real need.
- **Retention policy design for snapshots.** One file per run is enough until someone
  runs out of disk.

## Implementation status — 2026-10-02

- Implemented: service inventory, subject routes, explicit previewed writes, grantor,
  native findings, bridges, snapshots, declaration comparison and bounded CLI convergence.
- Subject and reverse route queries have no implicit route-count cap. Explicit callers
  may request a limit; cycles are cut. Large graphs still have combinatorial route cost.
- S3 unsupported/missing policies are unknown for affected identities, not every identity
  in the service. Unread whole endpoints remain service-wide unknown. No full IAM
  evaluator is attempted; conditional/negative policy semantics stay unknown.
- Console observations refresh in the background; cached reads use the last completed
  observation. Initial observations and explicit refreshes/writes may wait. Background
  observation and writes serialize; writes invalidate the cached result afterward.
- PostgreSQL/ClickHouse support opt-in subject login credentials before effective privilege
  evaluation. The default is observer-based. Probes do not verify data reads, RLS or writes.
- Regression evidence: `tests/test_prd_gaps.py`, plus existing page/write/snapshot/probe tests.
  Live subject login and operating-environment performance remain unverified.

Historical “Deliberately cut” items below are not required new work. Naming lint and map
views already exist; removing them is outside this correction.
