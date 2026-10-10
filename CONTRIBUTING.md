# Contributing Guide

This document explains the Git workflow, branch strategy, and commit conventions for this project. Following these rules ensures your GitHub Actions history looks professional for evaluators.

---

## Branch Strategy

```
main
 └── develop                  ← merge all features here first
      ├── feat/auth-keys       ← Phase 2, Step 1
      ├── feat/doc-encryption  ← Phase 2, Step 2
      ├── feat/group-keys      ← Phase 2, Step 3
      ├── feat/versions        ← Phase 2, Step 4
      ├── feat/comments        ← Phase 2, Step 5
      ├── feat/metadata-min    ← Phase 2, Step 6
      ├── feat/audit-log       ← Phase 2, Step 7
      ├── feat/realtime-sync   ← Phase 2, Step 8
      ├── feat/sse-search      ← Phase 3
      ├── chore/docker-setup   ← Phase 4
      └── chore/ci-cd          ← Phase 4
```

**Rule:** Never commit directly to `main` or `develop`. Always use a feature branch + Pull Request.

---

## Workflow for Every Feature

```bash
# 1. Start from develop (always up to date)
git checkout develop
git pull origin develop

# 2. Create your feature branch
git checkout -b feat/your-feature-name

# 3. Make small, focused commits as you go
git add -p                          # stage specific changes
git commit -m "feat(crypto): add AES-GCM document encryption"

# 4. Push your branch
git push origin feat/your-feature-name

# 5. Open a Pull Request → develop (not main)
#    Title must follow Conventional Commits (enforced by CI)

# 6. After PR is merged → develop gets deployed to staging
# 7. When develop is stable → merge develop → main (production)
```

---

## Commit Message Format (Conventional Commits)

Every commit message must follow this format:

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

### Types

| Type | When to use |
|---|---|
| `feat` | New feature (new endpoint, new UI component, new crypto operation) |
| `fix` | Bug fix |
| `test` | Adding or fixing tests |
| `docs` | Documentation only |
| `chore` | Build scripts, CI, dependencies, config |
| `refactor` | Code restructure without changing behavior |
| `perf` | Performance improvement (e.g. crypto optimization) |
| `ci` | GitHub Actions workflow changes |

### Scopes (optional but recommended)

`crypto`, `auth`, `docs`, `comments`, `search`, `audit`, `keys`, `db`, `api`, `ui`, `k8s`, `docker`

### Good commit message examples

```
feat(crypto): implement AES-GCM-256 document encryption

Uses WebCrypto API to encrypt document content client-side
before upload. Server receives only ciphertext blob.

Closes #12

feat(keys): add RSA-OAEP key wrapping for document sharing

fix(auth): handle expired JWT tokens gracefully

test(crypto): add round-trip encryption/decryption tests

chore(docker): add multi-stage Dockerfile for Go backend

perf(sse): reduce search index build time by 40%

docs: add sequence diagram for revoke flow
```

### Bad examples (will fail PR title check)

```
❌ fixed bug
❌ Update stuff
❌ WIP
❌ changes
❌ asdf
```

---

## Pull Request Rules

1. **Title** must follow Conventional Commits (`feat(scope): description`)
2. **Description** must include:
   - What you built
   - How to test it
   - Link to the related GitHub Issue (`Closes #N`)
3. **Size** keep PRs under 400 lines changed when possible
4. **Tests** every PR with new functionality must include tests
5. **CI must be green** before merging — no exceptions

---

## Suggested Feature Branch Schedule (14 weeks)

| Week | Branch | What you build |
|---|---|---|
| 1–2 | `docs/phase1-research` | Architecture diagrams, threat model |
| 3 | `docs/design-pack` | API contracts, UI wireframes |
| 4 | `feat/auth-key-derivation` | Login + PBKDF2 + RSA key gen |
| 5 | `feat/document-encryption` | AES-GCM upload/download |
| 6 | `feat/group-key-management` | Share + revoke + key wrapping |
| 7 | `feat/versions-comments` | Version history + encrypted comments |
| 8 | `feat/metadata-minimization` | Encrypt titles, pseudonymous audit |
| 8 | `feat/audit-log` | Tamper-evident SHA-256 chain |
| 9 | `feat/realtime-sync` | WebSocket + NATS collaboration |
| 9–10 | `feat/sse-search` | HMAC keyword index + SSE queries |
| 10 | `chore/docker-compose` | Full local stack |
| 11 | `chore/ci-cd` | GitHub Actions pipelines |
| 12 | `chore/kubernetes` | k8s manifests + monitoring |
| 13–14 | `docs/evaluation` | Test scripts + results + report |
