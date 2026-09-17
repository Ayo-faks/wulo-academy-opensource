# Wulo Academy

Wulo Academy is a learning platform for JSS/SS learners, parents, and teachers:
diagnostic practice, mastery tracking, a grounded tutor, safeguarding controls,
and progress reporting, built with a Flask backend and a React/TypeScript
frontend.

> **Status: portfolio developer preview.** This repository is a sanitized,
> allowlist-only export from an audited private source, published for
> demonstration purposes. Active product development continues in a separate
> private successor project, so maintenance here is best-effort. Nothing here
> is production-ready, clinically validated, or approved for real-child use.

## What Is Here Today

| Area | Contents |
| --- | --- |
| Publication tooling | `scripts/check_public_tree.py`, `scripts/build_public_export.py`, and their test suites |
| Governance | License, notices, trademark policy, contribution, security, support, conduct, governance, and maintainer records |
| Configuration examples | `.env.example` (offline local demo), `.env.azure.example` (optional cloud providers) |

## Planned Local Demo

The application import targets a credential-free local demo: SQLite/in-memory
persistence, synthetic identities, deterministic tutor fallback, telemetry off,
and no outbound provider calls. Azure OpenAI, Voice Live, Speech, Content
Safety, and telemetry remain optional adapters configured through
`.env.azure.example` values.

## License And Attribution

This project is licensed under the MIT License (see [LICENSE.md](LICENSE.md)).
It began from Microsoft's Azure-Samples Voice Live sample; original Microsoft
copyright notices are preserved, and [NOTICE.md](NOTICE.md) records the exact
upstream baseline. This project is independently maintained and is not
affiliated with, endorsed by, or supported by Microsoft.

## Safety Boundaries

- Source availability does not establish GDPR, UK Children's Code, clinical,
  diagnostic, or educational-efficacy compliance.
- Do not submit or commit real learner, child, parent, or customer data.
- Hosted deployments processing real children's data require their own legal,
  privacy, and safeguarding approval before operation.

## Community

- Contributions: [CONTRIBUTING.md](CONTRIBUTING.md) (DCO sign-off required)
- Security reports: [SECURITY.md](SECURITY.md)
- Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Support expectations: [SUPPORT.md](SUPPORT.md)
- Project stewardship: [GOVERNANCE.md](GOVERNANCE.md) and [MAINTAINERS.md](MAINTAINERS.md)
- Trademarks: [TRADEMARKS.md](TRADEMARKS.md)
