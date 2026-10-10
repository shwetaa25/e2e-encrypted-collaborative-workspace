#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
# Repository Setup Script
#
# Run this ONCE after cloning / creating the project.
# Sets up: git, branch protection rules, initial commit.
#
# Usage:
#   bash scripts/setup_repo.sh YOUR_GITHUB_USERNAME
# ─────────────────────────────────────────────────────────

set -e

GITHUB_USERNAME="${1:-YOUR_USERNAME}"
REPO_NAME="e2e-encrypted-workspace"

echo ""
echo "════════════════════════════════════════════════"
echo "  Project Repo Setup — $REPO_NAME"
echo "════════════════════════════════════════════════"
echo ""

# Step 1: Initialize git
echo "▶ Initializing git repository..."
git init
git config user.name "$GITHUB_USERNAME"

# Step 2: Create branch structure
echo "▶ Creating branch structure..."
# main       — production-ready code only
# develop    — integration branch (merge PRs here first)
# feat/*     — feature branches (e.g. feat/client-encryption)
# fix/*      — bug fixes
# chore/*    — non-code changes

git checkout -b main

# Step 3: Initial commit
echo "▶ Creating initial commit..."
cp .env.example .env.local 2>/dev/null || true
git add .
git commit -m "chore: initial project scaffold

Sets up the complete monorepo structure for the
End-to-End Encrypted Collaborative Workspace project.

Includes:
- Frontend (React + TypeScript + WebCrypto)
- Backend (Go + Gin + PostgreSQL)
- GitHub Actions CI/CD pipeline
- Docker Compose full local stack
- Kubernetes manifests
- Database schema (zero plaintext design)
- Confidentiality test script"

# Step 4: Create develop branch
git checkout -b develop
git push origin develop 2>/dev/null || echo "  (push to remote after GitHub repo is created)"

git checkout main

echo ""
echo "▶ Next steps:"
echo ""
echo "  1. Create a new GitHub repo at:"
echo "     https://github.com/new"
echo "     Name: $REPO_NAME"
echo "     Visibility: Private (for a university project)"
echo ""
echo "  2. Add remote and push:"
echo "     git remote add origin https://github.com/$GITHUB_USERNAME/$REPO_NAME.git"
echo "     git push -u origin main"
echo "     git push -u origin develop"
echo ""
echo "  3. Add GitHub Secrets (Settings → Secrets → Actions):"
echo "     POSTGRES_PASSWORD  — a strong random password"
echo "     JWT_SECRET         — output of: openssl rand -hex 32"
echo ""
echo "  4. Set branch protection on main:"
echo "     Settings → Branches → Add rule → main"
echo "     ✅ Require status checks (CI — Test, Build, Scan)"
echo "     ✅ Require PR before merging"
echo "     ✅ Require at least 1 approving review"
echo ""
echo "  5. Start coding! Create your first feature branch:"
echo "     git checkout develop"
echo "     git checkout -b feat/auth-and-key-derivation"
echo ""
echo "════════════════════════════════════════════════"
echo "  ✅ Setup complete!"
echo "════════════════════════════════════════════════"
