# ADR-0008: SOAR approval gates for dangerous actions

- Status: Accepted
- Date: 2026-10-07
- Deciders: Security engineering, SOC leadership, product

## Context

Bloody can act, not just observe. It can:

- isolate endpoints, kill processes and quarantine files;
- block IPs and domains;
- disable identities and revoke sessions or tokens.

Those actions run through engine adapters (Wazuh active response, Velociraptor, webhook relays to
customer firewalls and DNS, IdP connectors). A wrong isolation of a domain controller, or a
disabled CEO account, is an outage the security platform caused. Actions can be requested by:

- humans;
- playbooks reacting to events;
- the AI SOC.

For MSSPs, the action executes in a customer's environment on behalf of that customer.

## Decision

1. **Every action has a risk class** (`RESPONSE_ACTIONS` in `@bloody/contracts`).
   - `high`: isolate, block IP or domain, disable identity, revoke sessions or tokens.
   - `medium`: release, kill process, quarantine file.
   - `low`: case, notify, collect evidence, launch investigation, YARA scan, e-mail.
2. **High-risk actions always pass the `ApprovalGate`** (`@bloody/automation`). Policy can add
   classes, and a playbook step can force approval (`requireApproval`); policy can never remove
   `high`. The gate enforces:
   - the decider is a **human user** (service principals and API keys can never approve);
   - same tenant (otherwise the request reads as *not found*, so there is no existence oracle);
   - the `response:approve` permission **for the action's organization**;
   - **no self-approval**: neither the requester nor the human a playbook or AI acted for;
   - distinct approvers for multi-approval (four-eyes) policies, configurable 1–5 for
     high-risk actions;
   - pending and unexpired requests only. A TTL (default policy, max 7 days) closes stale
     requests as expired.
3. **Three permissions, separated.** `response:request` (analysts), `response:approve`
   (incident responders, CISOs, org admins) and `response:execute` (tier-2+, for low/medium
   actions). Customer roles can be granted approval for their own organization: in the
   customer portal a customer CISO approves isolating *their* host.
4. **Audit everything.** Each request, approval, rejection, expiry, denied attempt, execution and
   result is written to `audit_log` (append-only for the runtime role) with actor, tenant,
   organization, target, reason and request id.
5. **Playbooks** are versioned (`playbooks` / `playbook_versions`) with a trigger, conditions and
   ordered steps.
   - Global MSSP playbooks (`organizationId = null`) apply to every organization unless
     overridden per organization.
   - A run records each step. A step waiting for approval suspends the run, and the run resumes
     on decision.
6. **Executors are adapters.** Actions run through adapter action handlers
   (`wazuh.active_response`, `velociraptor.collect`, `webhook.block`, …) with idempotency keys,
   so a retried execution does not double-apply.
   - **Shuffle (AGPL, optional)** may be used as an executor for long-tail integrations, but
     only *after* Bloody's gate approves. Shuffle never decides.
   - Adapters declare how to undo an action when the engine supports it (release after isolate,
     unblock after block), so containment can be rolled back quickly.
7. **AI** requests go through the same gate (ADR-0007). The AI can never approve.

## Consequences

- No single person, playbook or model can execute a high-risk action alone, and every action is
  attributable after the fact.
- Containment can be slower during off-hours. Mitigations:
  - on-call approver rotations;
  - escalation notifications (`response.pending_approval` automation event);
  - customer-delegated approvers;
  - pre-approved, *low-risk* automated containment, such as collecting evidence or notifying.
- The gate's store (pending requests) is part of the transactional database. Approvals survive
  restarts and are visible to all replicas.

## Alternatives considered

- **Per-playbook "auto-approve" for high-risk actions.** Convenient, but it turns a playbook
  misconfiguration into an outage. Not allowed; only low or medium actions may run without a
  human.
- **Delegating decisions to the SOAR engine (Shuffle/TheHive responders).** That would split the
  audit trail and RBAC across products, and AGPL Shuffle would become a policy authority.
  Rejected; external SOAR is an executor only.
