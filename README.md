# GuardLayer Scan — free security scanner for Next.js + Supabase (GitHub Action)

**GuardLayer Scan is a free, open-source static security scanner for Next.js + Supabase apps that runs in your CI.** Drop it into any GitHub workflow and it catches the mistakes that actually leak data in these stacks — exposed secrets, missing Row Level Security, unverified webhooks, and unguarded Server Actions — and comments them inline on the pull request before they ship. No signup, no account, no code leaves your runner.

It runs the same static engine as [guardlayer.io](https://www.guardlayer.io).

## Quick start

Add `.github/workflows/guardlayer.yml`:

```yaml
name: GuardLayer
on: [pull_request, push]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: solvionsolutions/guardlayer-scan@v1
        with:
          fail-on: critical   # critical | warning | never
```

That's it. Findings appear as annotations on the exact file and line, plus a summary on the run. By default the build fails only on **critical** issues.

## What it checks

- **Supabase RLS** — tables with RLS disabled or missing, `USING (true)` policies, policies not scoped to the user.
- **Exposed secrets** — service-role keys and other secrets leaked through `NEXT_PUBLIC_`, hardcoded keys, connection strings.
- **Next.js app layer** — Server Actions and API routes with no auth check, wildcard CORS, missing middleware matchers.
- **Webhooks** — Stripe/webhook handlers that never verify the signature.
- **Dependencies** — known-vulnerable Next.js versions.
- **MCP configs** — secrets committed in `.mcp.json` / `.cursor/mcp.json`.

Precision-first: rules are tuned to stay quiet on safe code (a publishable Supabase anon key is *not* flagged as a secret, a zod-validated route is *not* flagged as unvalidated).

## Inputs

| Input | Default | Description |
|---|---|---|
| `fail-on` | `critical` | Fail the build on `critical`, on `warning` (and above), or `never` (report only). |

## Outputs

| Output | Description |
|---|---|
| `score` | Security score out of 100. |
| `grade` | Letter grade A–F. |
| `critical` / `warning` / `findings` | Finding counts. |

## Ignoring paths

Add a `.guardlayerignore` (gitignore syntax) to your repo root to exclude test fixtures or intentional examples. Vendor and build directories (`node_modules`, `.next`, `dist`, …) are always skipped.

## How it works

The Action walks your checked-out repo, runs GuardLayer's static analysis in-process, and emits GitHub annotations. It's pure static analysis — nothing is uploaded, no API key is required, and it works on private repos.

Want the same checks on every push with PR comments and a hosted dashboard, plus AI-written fixes? That's the hosted [GuardLayer](https://www.guardlayer.io) — free on one repository.

## License

MIT © GuardLayer / Solvion Solutions
