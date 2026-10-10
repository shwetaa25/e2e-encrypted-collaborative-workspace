# End-to-End Encrypted Collaborative Workspace

> A privacy-preserving document collaboration platform where the server stores **zero plaintext content**.  
> Master's Capstone Project — 3rd Semester

---

## Quick Start (3 commands)

```bash
git clone https://github.com/YOUR_USERNAME/e2e-encrypted-workspace.git
cd e2e-encrypted-workspace
docker compose up --build
```

Open **http://localhost:3000** — the full stack is running.

---

## What This System Does

| Feature | How it works |
|---|---|
| Document storage | AES-GCM-256 encrypted client-side before upload |
| Key sharing | RSA-OAEP key wrapping — server never holds plaintext keys |
| Access revoke | Key rotation — revoked user's wrapped key is cryptographically useless |
| Search | Searchable Symmetric Encryption (HMAC-indexed keyword search) |
| Comments | Encrypted with the document's AES key before transmission |
| Audit log | SHA-256 chained entries — tamper-evident |
| Metadata | Document titles and filenames encrypted — server sees only IDs |

**Server blindness guarantee:** Open PostgreSQL directly (`docker exec -it postgres psql -U postgres`) and `SELECT * FROM documents` — you will see zero plaintext content.

---

## Project Structure

```
e2e-encrypted-workspace/
├── frontend/              # React + TypeScript + WebCrypto API
│   └── src/
│       ├── crypto/        # All cryptographic operations (WebCrypto)
│       ├── components/    # UI components
│       ├── pages/         # Route pages
│       ├── hooks/         # React hooks
│       └── store/         # Zustand state management
├── backend/               # Go (Gin framework) REST API
│   ├── cmd/server/        # Main entrypoint
│   └── internal/
│       ├── handlers/      # HTTP route handlers
│       ├── models/        # Database models
│       ├── middleware/     # Auth, logging, CORS
│       ├── db/            # PostgreSQL queries
│       └── audit/         # Tamper-evident audit log
├── infra/
│   ├── k8s/               # Kubernetes manifests
│   ├── terraform/         # Cloud infrastructure
│   └── argocd/            # GitOps config
├── scripts/               # Seed scripts, test helpers
├── .github/workflows/     # CI/CD pipelines
└── docker-compose.yml     # Full local stack
```

---

## Services & Ports

| Service | Port | Description |
|---|---|---|
| Frontend | 3000 | React app (nginx) |
| Backend API | 8080 | Go REST API |
| PostgreSQL | 5432 | Encrypted document store |
| NATS | 4222 | Real-time sync message broker |
| Prometheus | 9090 | Metrics collection |
| Grafana | 3001 | Metrics dashboard (admin/admin) |
| Jaeger | 16686 | Distributed tracing (OpenTelemetry) |

---

## Test Users (pre-seeded)

| Email | Password | Role |
|---|---|---|
| alice@test.com | TestPass123! | Document owner |
| bob@test.com | TestPass123! | Collaborator |
| carol@test.com | TestPass123! | Reviewer (read-only) |
| admin@test.com | AdminPass123! | Admin |

---

## Running Tests

```bash
# Frontend unit tests
cd frontend && npm test

# Backend unit tests
cd backend && go test ./...

# Integration tests (requires running stack)
docker compose up -d
cd scripts && bash run_integration_tests.sh

# Confidentiality test (proves DB has no plaintext)
bash scripts/confidentiality_check.sh

# Load test (50 concurrent users)
k6 run scripts/load_test.js
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in values:

```bash
cp .env.example .env
```

Never commit `.env` — it is in `.gitignore`.

---

## Reproducibility

This repo is designed for full reproducibility:
- All dependencies are pinned (package-lock.json, go.sum)
- Database is seeded with synthetic test data via `scripts/seed.sql`
- All evaluation tests are automated scripts in `scripts/`
- Docker images are versioned and pushed to GitHub Container Registry

Another team can reproduce all evaluation results by running:
```bash
bash scripts/reproduce_evaluation.sh
```


---

## v2 Additions

### 1. Workspaces and per-file permissions
- Sidebar **Workspace** switcher: *Personal* or any workspace you belong to. **+ Workspace** creates one; the 👥 button manages members.
- The workspace name is AES-GCM encrypted in the browser; the workspace key is RSA-wrapped per member.
- **Being a member does not reveal files.** For each file the owner opens *Share* and ticks exactly which members get access (viewer / commenter / editor). Unticked members never receive the document key or ciphertext.
- Owners can change a member's level later from the Members tab (`PATCH /documents/{id}/members/{user}`) or fully revoke (key rotation).
- Removing someone from a workspace strips their keys for every file there.

### 2. Admin Console (separate from the workspace)
- Set `ADMIN_EMAILS` in `.env`, register that account, sign in: you land on the **Admin Console**.
- **Network log**: live list of every API request as the server received it, each field classified (ciphertext / wrapped key / search token / metadata). Passwords and tokens are redacted. Any readable text in a ciphertext field is flagged ⚠.
- **Server database view**: raw rows from PostgreSQL, all ciphertext.
- **Audit chain** verification and **Accounts** list. The admin cannot decrypt anything.

### 3. Account safety
- Emails are canonicalised (trim, lower-case, drop `+tag`) with a UNIQUE index, so changing only the email cannot create another account.
- Strong password enforced on both client (live checklist + strength bar) and server: 12+ chars, upper, lower, digit, special, no 3-in-a-row repeats, no spaces, not common, no email name.
- Per-IP registration throttle.

Existing databases: on start (development) the backend adds the new columns/tables automatically; `scripts/schema.sql` is idempotent for manual runs. If the canonical-email unique index cannot be created, duplicate accounts already exist and must be merged first.

---

## v3 Additions

### Usernames (emails stay private)
- Sign-up now asks for a **username** (3-20 chars, letters/numbers/underscore, starts with a letter, case-insensitive, unique).
- Adding someone to a workspace or sharing a file is done **by username only**. The email lookup endpoint was removed and no member list shows emails any more; the API returns only the username and public key.
- You can sign in with either your email or your username.
- Username lookups are rate-limited per user (`LOOKUP_MAX_PER_MINUTE`, default 30) to make guessing harder.
- Accounts created before this version get a username derived from their email (e.g. `john.doe@x.com` becomes `john_doe`) on startup.

### Live updates (no manual refresh)
- The workspace polls `GET /api/v1/sync/poll` every 3 seconds (and when the tab regains focus). It returns only ids and a fingerprint, no titles or ciphertext.
- When a file is shared with you, your permission changes, you are added to a workspace, or access is revoked, the lists update by themselves and a toast appears.
- This endpoint is deliberately left out of the Admin network log so the 3-second polling does not flood it.

---

## v4 Additions

### Admin: delete users
- Admin Console → **Accounts** → **Delete**. A confirmation dialog first shows exactly what will be removed (owned documents, how many are shared with others, owned workspaces, memberships) and requires typing the username.
- Deleted: the account, documents it owns, workspaces it owns (with every file inside), and its keys/memberships elsewhere. Other people's documents survive; the deleted user's edits there are re-attributed to the document owner.
- Safeguards: admins cannot delete themselves or other admin accounts (remove the email from `ADMIN_EMAILS` first); every delete is recorded in the tamper-evident audit chain.
- The admin still cannot read anything: only ciphertext is removed.


### Admin: delete users and workspaces
- **Accounts** tab: *Delete* removes a user (with a preview of what disappears, and you must type their username to confirm). Admins and yourself cannot be deleted.
- **Workspaces** tab: lists every workspace (owner, members, file count; names stay encrypted) and lets the admin delete any of them with all files inside.
- A user whose account was deleted is signed out automatically within a few seconds.
- Deleting only removes ciphertext; the admin still cannot read any content.

---

## v4 Additions

- **Admin can delete accounts** (Admin Console → Accounts → Delete). Removes the user's documents (including shared copies), workspaces, keys, comments and memberships; shows counts in the confirmation. Admin accounts and your own account cannot be deleted. A deleted user is signed out automatically within a few seconds.
- **Admin can delete any workspace** (Admin Console → Workspaces). Names appear as ciphertext, because the admin cannot decrypt them.
- **Workspace owners** now have a visible 🗑 button in the sidebar to delete their own workspace (also still available in the members dialog).
- **Save button** in the top bar with an "Unsaved changes / All changes saved" indicator, **Ctrl+S**, a browser warning when closing the tab with unsaved edits, and an **Auto-save** checkbox (off by default; remembered per browser).
- All deletions are recorded in the tamper-evident audit chain.
