# vulnerable-demo-app

**Intentionally vulnerable** Node.js app used as a fixture for the VulnFix
agent POC. Do not deploy. Do not copy any of these version pins into a real
project.

The app pins three direct dependencies at versions chosen to produce a
specific mix of `npm audit` findings — one of them transitive — that
exercise the agent's fix planner.

## The three vulnerabilities

| # | Package | Pinned version | Kind | Severity | Advisory (latest in chain) | `npm audit fix` without `--force`? |
|---|---|---|---|---|---|---|
| 1 | `axios` | `1.7.3` | **Direct** | high | GHSA-8hc4-vh64-cxmj (SSRF), GHSA-4hjh-wcwx-xvwj (DoS), and others | ❌ No — fix (`1.15.0`) is outside the exact pin |
| 2 | `handlebars` | `4.7.6` | **Direct** | critical | GHSA-2qvq-rjwj-gvw9 (XSS via partial prototype pollution) and others | ❌ No — fix (`4.7.9`) is outside the exact pin |
| 3 | `protobufjs` | `6.11.5` (resolved) | **Transitive** via `@grpc/proto-loader@0.5.6` | critical | GHSA-xq3m-2v4x-88gg (arbitrary code execution via prototype pollution) | ❌ No — requires a SemVer-**major** bump of `@grpc/proto-loader` |

All three deps are pinned exactly (no `^`, no `~`), which means none of the
available fixes are inside the declared ranges. This is a deliberate
choice for the fixture — it produces a reproducible, stable set of
findings every time someone clones and installs, independent of whatever
`~` or `^` would float to on any given day.

The planner in this POC has two action types:

- `npm_audit_fix` — runs `npm audit fix`, which only helps when (a) the
  fix is inside the declared range **and** (b) the installed version is
  older than the fix. With exact pins, (a) is never true, so `audit fix`
  is a no-op here.
- `package_update` — installs a specific package at a specific version,
  regardless of the declared range. This is what the fixture exercises.

A follow-up fixture that exercises the `npm_audit_fix` path cleanly would
need either caret-pinned deps **plus a committed `package-lock.json`
pinning older versions**, or a stale transitive dep hoisted from a
deeper tree. That's worth adding, but is out of scope for this first
fixture.

## Dependency tree (after install)

```
vulnerable-demo-app@1.0.0
├── @grpc/proto-loader@0.5.6
│   ├── lodash.camelcase@4.3.0
│   └── protobufjs@6.11.5      ◄── TRANSITIVE VULN
├── axios@1.7.3                ◄── DIRECT VULN
└── handlebars@4.7.6           ◄── DIRECT VULN
```

## Why this is still a good POC fixture

The third dependency is the interesting one. `protobufjs` is not a direct
dependency — the planner cannot just "update protobufjs", because running
`npm install protobufjs@7.5.5` would add it as a **new** direct dep
rather than fix the transitive install under `@grpc/proto-loader`. The
correct remediation is one of:

1. **Major-bump the parent**: `npm install @grpc/proto-loader@0.8.0`.
   This is what `npm audit` itself suggests (`Will install
   @grpc/proto-loader@0.8.0, which is a breaking change`) and what
   real-world scanners (Dependabot, Snyk, GitHub Advanced Security)
   surface: they report the direct dep that needs to change, not the
   transitively-vulnerable package. The agent's `package_update` action
   handles this naturally.
2. **Add an `overrides` block** in `package.json` forcing `protobufjs`
   to a safe version. This is a deeper fix (doesn't require bumping
   `@grpc/proto-loader`), but requires a new Tools API endpoint — say,
   `PATCH /workspaces/{id}/package-json` — that can write a structured
   edit to `package.json`. That's a natural next extension of the POC.

The fixture demonstrates path (1) today. Path (2) is the logical
extension that proves overrides work when you need them.

## Reproduce the findings

```bash
cd vulnerable-demo-app
npm install
npm audit
```

Expected summary (exact counts will drift as new advisories are
published):

```
axios  1.0.0 - 1.14.0
Severity: high
...
fix available via `npm audit fix --force`
Will install axios@1.15.0, which is outside the stated dependency range

handlebars  <=4.7.8
Severity: critical
...
fix available via `npm audit fix --force`
Will install handlebars@4.7.9, which is outside the stated dependency range

@grpc/proto-loader  <=0.6.13
Depends on vulnerable versions of protobufjs
...
fix available via `npm audit fix --force`
Will install @grpc/proto-loader@0.8.0, which is a breaking change

protobufjs  <7.5.5
Severity: critical
Arbitrary code execution in protobufjs
...

4 vulnerabilities (1 high, 3 critical)
```

The full audit output at the time this fixture was assembled is checked
in at `AUDIT_SNAPSHOT.txt` for reference.

## Driving the agent against this app

Once the Tools API and Agent API are running (see the main POC README),
push this fixture to a git remote, then:

```bash
curl -X POST http://localhost:8002/remediate \
  -H 'Content-Type: application/json' \
  -d '{
    "repo_url": "https://github.com/<your-org>/vulnerable-demo-app.git",
    "branch": "main",
    "vulnerabilities": [
      {
        "id": "GHSA-8hc4-vh64-cxmj",
        "package": "axios",
        "current_version": "1.7.3",
        "fixed_version": "1.15.0",
        "severity": "high",
        "description": "SSRF via absolute URL override in axios requests"
      },
      {
        "id": "GHSA-2qvq-rjwj-gvw9",
        "package": "handlebars",
        "current_version": "4.7.6",
        "fixed_version": "4.7.9",
        "severity": "critical",
        "description": "Prototype pollution leading to XSS via partial template injection"
      },
      {
        "id": "GHSA-xq3m-2v4x-88gg",
        "package": "@grpc/proto-loader",
        "current_version": "0.5.6",
        "fixed_version": "0.8.0",
        "severity": "critical",
        "description": "Transitive: protobufjs prototype pollution; requires major bump of @grpc/proto-loader"
      }
    ]
  }'
```

Note the third entry targets the **parent** package (`@grpc/proto-loader`),
not the transitively-vulnerable `protobufjs`. That matches how real
scanners report transitive vulnerabilities: they surface the direct
dependency that needs to change.

## What a successful run should produce

A correct plan for this fixture has three targeted updates, no audit-fix
action:

```json
[
  {
    "type": "package_update",
    "package": "axios",
    "target_version": "1.15.0",
    "reason": "Scanner-reported fix; out of range for plain audit fix",
    "addresses": ["GHSA-8hc4-vh64-cxmj"]
  },
  {
    "type": "package_update",
    "package": "handlebars",
    "target_version": "4.7.9",
    "reason": "Scanner-reported fix; out of range for plain audit fix",
    "addresses": ["GHSA-2qvq-rjwj-gvw9"]
  },
  {
    "type": "package_update",
    "package": "@grpc/proto-loader",
    "target_version": "0.8.0",
    "reason": "Major bump required; carries transitive protobufjs fix",
    "addresses": ["GHSA-xq3m-2v4x-88gg"]
  }
]
```

After execution, `npm audit` should report zero vulnerabilities and the
agent should produce a single commit touching `package.json` and
`package-lock.json`.

### A subtlety about correlating scanner reports with audit output

The scanner report names `@grpc/proto-loader` (the direct dependency
that needs to change), but `npm audit` names `protobufjs` (the actually
vulnerable package). The planner has to correlate them. The current
planner prompt handles this because it's told to prefer `package_update`
when the scanner gives an explicit `fixed_version`, and the scanner
report names the parent package.

A deterministic-path improvement worth considering: when an `npm audit`
entry's `fixAvailable` object names a *different* package than the
vulnerable one, the system could prefer a `package_update` on the
named parent package regardless of what the LLM suggests. That would
make the transitive case handled without LLM involvement at all, and
would also guard against the LLM hallucinating a direct-install of the
transitively-vulnerable package.
#   v u l n - t e s t  
 