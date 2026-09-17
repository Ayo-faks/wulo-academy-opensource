# Contributing to Wulo Academy

Thank you for helping improve Wulo Academy. Contributions are accepted under
the MIT license with a Developer Certificate of Origin (DCO) sign-off.

## Developer Certificate Of Origin

Every commit must be signed off, certifying the
[DCO 1.1](https://developercertificate.org/):

```bash
git commit -s -m "feat: your change"
```

This appends `Signed-off-by: Your Name <you@example.com>`. Pull requests with
unsigned commits cannot be merged. There is no CLA.

## Ground Rules

- **Never include real personal data.** Issues, pull requests, tests, and
  fixtures must use clearly synthetic learners, parents, teachers, and metrics.
- **Never commit secrets.** No `.env` files, keys, tokens, certificates,
  connection strings, or databases. Use the checked-in `.env.example` files.
- **New dependencies need review.** State the license of any added dependency
  in the pull request; incompatible or unreviewed licenses are declined.
- **New binaries or content need provenance.** Assets require an owner,
  source, and license record before they can merge.
- **Safety-relevant changes need extra scrutiny.** Changes to safeguarding,
  authentication, consent, data export/erasure, or child-facing copy must
  describe their impact in the pull request.

## Workflow

1. Fork and create a feature branch.
2. Make focused changes with tests.
3. Run the checks below and ensure they pass.
4. Open a pull request describing the change, tests, and any dependency,
   data, privacy, or safety impact.

## Checks

```bash
# Backend
cd backend && python -m pytest -q && flake8 . --config=.flake8 && black . --check --config pyproject.toml

# Frontend
cd frontend && npm ci && npm run lint && npm run format:check && npm test && npm run build
```

## Conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
