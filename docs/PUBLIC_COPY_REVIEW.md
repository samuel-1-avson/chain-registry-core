# Public copy review (MAIN-007 / L2 gate)

**Reviewed:** 2026-06-12  
**Scope:** Hub web, public quickstart, operator docs visible to external users  
**Verdict:** Pass for in-repo surfaces; white paper and social remain operator-owned outside this repo.

## Checked surfaces

| Surface | Status | Notes |
|---------|--------|-------|
| `hub-web` AlphaDisclaimer | Pass | "Public alpha — not mainnet or production" |
| `hub-web` HomePage / NetworkPage / FaqPage | Pass | Alpha framing; no mainnet-ready claims |
| `docs/PUBLIC_TESTNET_QUICKSTART.md` | Pass | SEC-401 + alpha limitations section |
| `docs/TESTNET_PHASE_SCOPE.md` | Pass | Defines verified/pending honestly |
| `docs/L2_PUBLIC_ALPHA_GATE_STATUS.md` | Pass | Tracks partial gates explicitly |

## Out of repo (manual before wide marketing)

| Surface | Action |
|---------|--------|
| White paper (`CREG_WHITEPAPER` draft) | Keep "testnet / public alpha" framing; no production security claims until SEC-401 closes |
| Social posts (X, LinkedIn, etc.) | Use hub FAQ language: coordinated testnet, waitlist, not mainnet |
| Waitlist landing copy | Firebase deploy — confirm matches hub disclaimers |

## Banned phrases (until SEC-401 + L3)

- "Production-ready" / "mainnet-ready" / "enterprise-grade security"
- "Audited" without naming vendor + report date
- "Guaranteed" package safety (use "verified after validator quorum")

## Sign-off

In-repo public copy is **alpha-safe** for waitlist + testnet onboarding. Widen marketing only after SEC-401 vendor is booked.
