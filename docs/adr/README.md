# Architecture Decision Records

Each ADR records one significant, hard-to-reverse decision: the context that forced it, what was
decided, what it costs, and which alternatives were rejected and why. ADRs are immutable once
accepted. To change a decision, add a new ADR that supersedes the old one and update the old
one's status line only.

| # | Decision | Status |
|---|---|---|
| [0001](0001-typescript-monorepo-modular-monolith.md) | TypeScript monorepo and modular monolith | Accepted |
| [0002](0002-postgres-rls-tenancy.md) | Tenancy in PostgreSQL with row-level security | Accepted |
| [0003](0003-canonical-event-schema.md) | Bloody Canonical Event (BCE) schema | Accepted |
| [0004](0004-open-source-engines-and-licence-policy.md) | Open-source engines via adapters, and the licence policy | Accepted |
| [0005](0005-security-graph-in-postgres.md) | Security Graph stored in PostgreSQL first | Accepted |
| [0006](0006-explainable-risk-engine.md) | Explainable risk engine | Accepted |
| [0007](0007-ai-provider-abstraction-and-tool-tiers.md) | AI provider abstraction and tool permission tiers | Accepted |
| [0008](0008-soar-approval-gates.md) | SOAR approval gates for dangerous actions | Accepted |
| [0009](0009-mssp-tenancy-and-customer-portal.md) | MSSP tenancy model and customer portal | Accepted |
| [0010](0010-reporting-and-notifications.md) | Reporting and notifications | Accepted |

## Template

```markdown
# ADR-NNNN: <decision in a few words>

- Status: Proposed | Accepted | Superseded by ADR-XXXX
- Date: YYYY-MM-DD
- Deciders: <roles>

## Context
What forces are at play: requirements, constraints, risks.

## Decision
What we do, stated so a new engineer can follow it.

## Consequences
What gets easier, what gets harder, and what we must now maintain.

## Alternatives considered
Each option, and why it lost.
```

Related documents: [ARCHITECTURE](../ARCHITECTURE.md), [OPERATIONS](../OPERATIONS.md),
[LICENSES](../LICENSES.md), [MSSP](../MSSP.md).
