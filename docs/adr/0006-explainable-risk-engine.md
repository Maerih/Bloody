# ADR-0006: Explainable risk engine

- Status: Accepted
- Date: 2026-10-07
- Deciders: Detection engineering, product, platform architecture

## Context

Bloody prioritizes everything with scores: assets, identities, incidents, vulnerabilities,
exposure, attack paths, customer portfolios. Analysts, CISOs and MSSP customers act on those
scores (patch first, isolate, escalate), so a score nobody can explain is untrustworthy and
indefensible in a customer review. Common pitfalls:

- additive "alert count" scores, where volume beats severity;
- opaque ML scores;
- scores that silently change meaning between releases.

## Decision

1. **Every score carries an explanation.** `RiskAssessment` (`packages/contracts/src/graph.ts`)
   holds:
   - `score` (0–100), `severity`, `likelihood`, `impact`;
   - `factors: RiskFactor[]`, where each factor has `key`, `label`, normalized `value`,
     `weight`, signed `contribution` in points, and a human-readable `explanation`;
   - a `summary` and a `modelVersion`.

   APIs and reports never return a bare number.
2. **One documented model for all subjects** (`packages/engines/src/risk/model.ts`,
   `RISK_MODEL_VERSION = "bloody-risk/1.0.0"`):
   - **Combination.** Likelihood and impact signals combine with a noisy-OR in hazard space
     (`h = −ln(1 − w·v)`): independent evidence reinforces but saturates, so ten weak signals
     cannot outweigh one strong one.
   - **Controls.** Compensating controls such as MFA, EDR coverage and segmentation reduce
     likelihood multiplicatively.
   - **Calibration.** Raw risk `L × I` maps through a monotone logistic curve (k = 6,
     m = 0.24), anchored so that (0.5, 0.5) → 41 *medium* and (0.8, 0.8) → 90 *critical*.
   - **Exact attribution.** Positive factors share the unreduced score in proportion to their
     hazard. Controls share the (negative) reduction. Contributions sum *exactly* to the
     displayed score, with the rounding residual assigned to the largest factor.
3. **Subject-specific factor sets** (asset, identity, incident, vulnerability, exposure, attack
   path) are versioned as `bloody-risk/<semver>#<subject>`. Inputs are documented signals, for
   example:
   - vulnerabilities: CVSS, EPSS, CISA KEV, internet exposure, criticality (crown jewel),
     privilege, threat-intel matches;
   - identities: MFA, privileged access.
4. **Determinism.** The model is pure (an injected clock, no randomness), so the same inputs
   always give the same score and factors. Tests pin the anchors.
5. **Change control.** Changing weights, curve or factor sets bumps `modelVersion`. Stored
   assessments keep the version they were computed with. Reports show the version, and portfolio
   comparisons never mix versions without recomputation.
6. **AI never sets scores.** The AI SOC may *explain* a score from its factors, and may *propose*
   a manual adjustment that goes through normal RBAC. It cannot write one.

## Consequences

- Analysts and customers can see *why* something is critical and *what would lower it*. Attack
  paths list remediations ordered by paths broken, each with its own explained risk.
- MSSP portfolio comparisons are meaningful, because every customer is scored by the same
  versioned model.
- Tuning is explicit work (weights in code, reviewed, versioned) rather than silent drift.
- A learned model (for example for alert triage confidence) can be added later only as an
  additional, explainable factor with its own label and explanation. It never replaces the
  attribution.

## Alternatives considered

- **Additive point systems.** Easy to explain, but unbounded and volume-dominated. Rejected.
- **CVSS-only or vendor scores.** No context (exposure, criticality, controls, identity
  privilege) and not comparable across sources. Kept only as input factors.
- **Opaque ML risk scores.** Unexplainable to customers, and hard to defend in incident reviews
  and audits. Rejected for headline scores.
