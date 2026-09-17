# Governance

## Model

Wulo Academy currently uses a single-maintainer ("benevolent dictator")
model. The lead maintainer owns final decisions on scope, releases, security
response, and policy, and delegates review as the maintainer team grows.

## Decision Making

- Routine changes: pull request review by a maintainer.
- Significant changes (architecture, public API, safety, licensing,
  governance): a GitHub issue or discussion first, decided by the lead
  maintainer after community input.
- Security decisions follow [SECURITY.md](SECURITY.md) and may be made
  privately until a fix is released.

## Roles

| Role | Authority |
| --- | --- |
| Lead maintainer | Final decisions, releases, security response, maintainer appointments |
| Maintainer | Review and merge, triage, release preparation |
| Contributor | Anyone submitting issues or DCO-signed pull requests |

Maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md). Maintainers are
appointed and removed by the lead maintainer; sustained, high-quality
contribution is the path to maintainership.

## Releases

Releases are tagged from `main` by a maintainer only after the required checks
pass. Release authority rests with the lead maintainer.

## Succession

If the lead maintainer becomes unavailable, the listed maintainers jointly
select a successor; the trademark owner retains naming decisions under
[TRADEMARKS.md](TRADEMARKS.md).

## Changes To Governance

Changes to this document are proposed by pull request and decided by the lead
maintainer.
