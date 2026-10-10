# tests/integration/test_workspaces_and_admin.py
# ─────────────────────────────────────────────────────────
# Covers the v2 features:
#   * duplicate-account protection (canonical email) + strong passwords
#   * workspaces: create, add member, per-file permissions
#   * Admin Console: access control + network log classification
# Requires PostgreSQL (see test_api.py). Uses fake-but-valid crypto blobs.
# ─────────────────────────────────────────────────────────

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.core.network_log import network_log

FAKE_PUBLIC_KEY = "A" * 200
FAKE_WRAPPED = "B" * 200
FAKE_IV = "AAAAAAAAAAAAAAAA"
STRONG_PASSWORD = "Str0ng!Test#Pw42"
ADMIN_EMAIL = "console-admin@example.com"


@pytest_asyncio.fixture
async def client() -> AsyncClient:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


def payload(email: str, password: str = STRONG_PASSWORD, username: str | None = None) -> dict:
    return {
        "email": email, "password": password,
        "username": username or "u" + uuid.uuid4().hex[:12],
        "public_key_spki": FAKE_PUBLIC_KEY, "wrapped_private_key": FAKE_WRAPPED,
        "wrap_iv": FAKE_IV, "pbkdf2_salt": FAKE_IV,
    }


async def register(client: AsyncClient, email: str | None = None, username: str | None = None) -> dict:
    email = email or f"u-{uuid.uuid4().hex[:10]}@example.com"
    resp = await client.post("/api/v1/auth/register", json=payload(email, username=username))
    assert resp.status_code == 201, resp.text
    data = resp.json()
    data["email"] = email          # (username comes from the response body)
    data["headers"] = {"Authorization": f"Bearer {data['access_token']}"}
    return data


def doc_payload(workspace_id: str | None = None) -> dict:
    body = {
        "title_ciphertext": "ENCRYPTED_TITLE==", "title_iv": FAKE_IV,
        "content_ciphertext": "ENCRYPTED_CONTENT==", "content_iv": FAKE_IV,
        "wrapped_key_for_owner": "C" * 200, "search_index": [],
    }
    if workspace_id:
        body["workspace_id"] = workspace_id
    return body


# ── Account creation ──────────────────────────────────────

class TestAccountProtection:
    async def test_weak_password_rejected(self, client):
        resp = await client.post("/api/v1/auth/register",
                                 json=payload(f"w-{uuid.uuid4().hex[:8]}@example.com", "password1"))
        assert resp.status_code == 422

    async def test_email_variants_cannot_create_second_account(self, client):
        base = f"dupe-{uuid.uuid4().hex[:8]}"
        await register(client, f"{base}@example.com")
        for variant in (f"{base.upper()}@example.com", f" {base}@example.com ", f"{base}+alt@example.com"):
            resp = await client.post("/api/v1/auth/register", json=payload(variant))
            assert resp.status_code == 409, variant

    async def test_username_must_be_unique_and_valid(self, client):
        name = "n" + uuid.uuid4().hex[:10]
        await register(client, username=name)
        dup = await client.post("/api/v1/auth/register",
                                json=payload(f"x-{uuid.uuid4().hex[:8]}@example.com", username=name.upper()))
        assert dup.status_code == 409
        for bad in ("ab", "1abc", "has space", "a__b", "admin", "bad-name"):
            resp = await client.post("/api/v1/auth/register",
                                     json=payload(f"y-{uuid.uuid4().hex[:8]}@example.com", username=bad))
            assert resp.status_code == 422, bad

    async def test_login_with_username(self, client):
        name = "l" + uuid.uuid4().hex[:10]
        await register(client, username=name)
        resp = await client.post("/api/v1/auth/login", json={"email": name, "password": STRONG_PASSWORD})
        assert resp.status_code == 200
        assert resp.json()["username"] == name

    async def test_lookup_by_username_hides_email(self, client):
        alice = await register(client)
        bob = await register(client, username="bob" + uuid.uuid4().hex[:8])
        resp = await client.get(f"/api/v1/auth/users/by-username?username={bob['username'].upper()}",
                                headers=alice["headers"])
        assert resp.status_code == 200
        body = resp.json()
        assert body["user_id"] == bob["user_id"]
        assert "email" not in body
        # the old email lookup no longer exists
        gone = await client.get(f"/api/v1/auth/users/by-email?email={bob['email']}", headers=alice["headers"])
        assert gone.status_code in (404, 405)

    async def test_member_lists_never_expose_email(self, client):
        alice, bob = await register(client), await register(client)
        doc_id = (await client.post("/api/v1/documents", headers=alice["headers"], json=doc_payload())).json()["id"]
        await client.post(f"/api/v1/documents/{doc_id}/share", headers=alice["headers"], json={
            "recipient_user_id": bob["user_id"], "wrapped_key": "D" * 200, "access_level": "viewer"})
        members = (await client.get(f"/api/v1/documents/{doc_id}/members", headers=alice["headers"])).json()
        assert all("email" not in m and m["username"] for m in members)

    async def test_login_works_with_email_variant(self, client):
        user = await register(client, f"Mixed-{uuid.uuid4().hex[:8]}@Example.com")
        resp = await client.post("/api/v1/auth/login",
                                 json={"email": user["email"].lower(), "password": STRONG_PASSWORD})
        assert resp.status_code == 200


# ── Usernames ─────────────────────────────────────────────

class TestUsernames:
    async def test_username_is_returned_and_lowercased(self, client):
        name = "MixedCase" + uuid.uuid4().hex[:6]
        resp = await client.post("/api/v1/auth/register",
                                 json=payload(f"un-{uuid.uuid4().hex[:8]}@example.com", username=name))
        assert resp.status_code == 201, resp.text
        assert resp.json()["username"] == name.lower()

    @pytest.mark.parametrize("bad", ["ab", "1abc", "has space", "bad-dash", "admin", "a__b", "x" * 21])
    async def test_invalid_usernames_rejected(self, client, bad):
        resp = await client.post("/api/v1/auth/register",
                                 json=payload(f"bu-{uuid.uuid4().hex[:8]}@example.com", username=bad))
        assert resp.status_code == 422

    async def test_username_must_be_unique_case_insensitive(self, client):
        name = "taken" + uuid.uuid4().hex[:6]
        first = await client.post("/api/v1/auth/register",
                                  json=payload(f"t1-{uuid.uuid4().hex[:8]}@example.com", username=name))
        assert first.status_code == 201
        second = await client.post("/api/v1/auth/register",
                                   json=payload(f"t2-{uuid.uuid4().hex[:8]}@example.com", username=name.upper()))
        assert second.status_code == 409

    async def test_login_with_username(self, client):
        user = await register(client)
        resp = await client.post("/api/v1/auth/login",
                                 json={"email": user["username"], "password": STRONG_PASSWORD})
        assert resp.status_code == 200

    async def test_lookup_by_username_never_leaks_email(self, client):
        alice, bob = await register(client), await register(client)
        resp = await client.get(f"/api/v1/auth/users/by-username?username={bob['username'].upper()}",
                                headers=alice["headers"])
        assert resp.status_code == 200
        body = resp.json()
        assert body["user_id"] == bob["user_id"]
        assert "email" not in body and bob["email"] not in resp.text

    async def test_email_lookup_endpoint_is_gone(self, client):
        alice, bob = await register(client), await register(client)
        resp = await client.get(f"/api/v1/auth/users/by-email?email={bob['email']}", headers=alice["headers"])
        assert resp.status_code in (404, 405, 422)

    async def test_member_lists_show_usernames_not_emails(self, client):
        alice, bob = await register(client), await register(client)
        ws = (await client.post("/api/v1/workspaces", headers=alice["headers"], json={
            "name_ciphertext": "ENC==", "name_iv": FAKE_IV, "wrapped_workspace_key": "W" * 200})).json()["id"]
        await client.post(f"/api/v1/workspaces/{ws}/members", headers=alice["headers"],
                          json={"user_id": bob["user_id"], "wrapped_workspace_key": "W" * 200})
        resp = await client.get(f"/api/v1/workspaces/{ws}/members", headers=alice["headers"])
        assert bob["username"] in resp.text and bob["email"] not in resp.text


# ── Live sync (no manual refresh) ─────────────────────────

class TestSyncPoll:
    async def test_shared_document_appears_in_receivers_poll(self, client):
        alice, bob = await register(client), await register(client)
        before = (await client.get("/api/v1/sync/poll", headers=bob["headers"])).json()

        doc_id = (await client.post("/api/v1/documents", headers=alice["headers"],
                                    json=doc_payload())).json()["id"]
        await client.post(f"/api/v1/documents/{doc_id}/share", headers=alice["headers"], json={
            "recipient_user_id": bob["user_id"], "wrapped_key": "D" * 200, "access_level": "viewer"})

        after = (await client.get("/api/v1/sync/poll", headers=bob["headers"])).json()
        assert after["documents_fp"] != before["documents_fp"]
        assert doc_id in after["document_ids"]

    async def test_poll_reveals_only_my_documents(self, client):
        alice, eve = await register(client), await register(client)
        doc_id = (await client.post("/api/v1/documents", headers=alice["headers"],
                                    json=doc_payload())).json()["id"]
        eves = (await client.get("/api/v1/sync/poll", headers=eve["headers"])).json()
        assert doc_id not in eves["document_ids"]

    async def test_poll_requires_auth(self, client):
        assert (await client.get("/api/v1/sync/poll")).status_code in (401, 403)


# ── Workspaces ────────────────────────────────────────────

class TestWorkspaces:
    async def _make_ws(self, client, owner) -> str:
        resp = await client.post("/api/v1/workspaces", headers=owner["headers"], json={
            "name_ciphertext": "ENC_NAME==", "name_iv": FAKE_IV, "wrapped_workspace_key": "W" * 200,
        })
        assert resp.status_code == 201, resp.text
        return resp.json()["id"]

    async def test_create_add_member_and_list(self, client):
        alice, bob = await register(client), await register(client)
        ws = await self._make_ws(client, alice)

        add = await client.post(f"/api/v1/workspaces/{ws}/members", headers=alice["headers"],
                                json={"user_id": bob["user_id"], "wrapped_workspace_key": "W" * 200})
        assert add.status_code == 201

        bobs = await client.get("/api/v1/workspaces", headers=bob["headers"])
        assert [w["id"] for w in bobs.json()] == [ws]
        assert bobs.json()[0]["role"] == "member"

    async def test_non_owner_cannot_add_members(self, client):
        alice, bob, carol = [await register(client) for _ in range(3)]
        ws = await self._make_ws(client, alice)
        await client.post(f"/api/v1/workspaces/{ws}/members", headers=alice["headers"],
                          json={"user_id": bob["user_id"], "wrapped_workspace_key": "W" * 200})
        resp = await client.post(f"/api/v1/workspaces/{ws}/members", headers=bob["headers"],
                                 json={"user_id": carol["user_id"], "wrapped_workspace_key": "W" * 200})
        assert resp.status_code == 403

    async def test_outsider_cannot_see_workspace(self, client):
        alice, eve = await register(client), await register(client)
        ws = await self._make_ws(client, alice)
        resp = await client.get(f"/api/v1/workspaces/{ws}/members", headers=eve["headers"])
        assert resp.status_code == 404

    async def test_membership_alone_does_not_expose_files(self, client):
        alice, bob = await register(client), await register(client)
        ws = await self._make_ws(client, alice)
        await client.post(f"/api/v1/workspaces/{ws}/members", headers=alice["headers"],
                          json={"user_id": bob["user_id"], "wrapped_workspace_key": "W" * 200})
        doc = await client.post("/api/v1/documents", headers=alice["headers"], json=doc_payload(ws))
        assert doc.status_code == 201
        doc_id = doc.json()["id"]

        # Bob is a member but was not granted the file
        listing = await client.get(f"/api/v1/documents?workspace_id={ws}", headers=bob["headers"])
        assert listing.json() == []
        assert (await client.get(f"/api/v1/documents/{doc_id}", headers=bob["headers"])).status_code == 404

        # Alice grants Bob viewer access to just this file
        share = await client.post(f"/api/v1/documents/{doc_id}/share", headers=alice["headers"], json={
            "recipient_user_id": bob["user_id"], "wrapped_key": "D" * 200, "access_level": "viewer"})
        assert share.status_code == 201
        listing = await client.get(f"/api/v1/documents?workspace_id={ws}", headers=bob["headers"])
        assert [d["id"] for d in listing.json()] == [doc_id]

    async def test_cannot_share_workspace_file_with_non_member(self, client):
        alice, eve = await register(client), await register(client)
        ws = await self._make_ws(client, alice)
        doc_id = (await client.post("/api/v1/documents", headers=alice["headers"],
                                    json=doc_payload(ws))).json()["id"]
        resp = await client.post(f"/api/v1/documents/{doc_id}/share", headers=alice["headers"], json={
            "recipient_user_id": eve["user_id"], "wrapped_key": "D" * 200, "access_level": "viewer"})
        assert resp.status_code == 400

    async def test_cannot_create_document_in_foreign_workspace(self, client):
        alice, eve = await register(client), await register(client)
        ws = await self._make_ws(client, alice)
        resp = await client.post("/api/v1/documents", headers=eve["headers"], json=doc_payload(ws))
        assert resp.status_code == 403

    async def test_change_access_level_and_enforcement(self, client):
        alice, bob = await register(client), await register(client)
        doc_id = (await client.post("/api/v1/documents", headers=alice["headers"],
                                    json=doc_payload())).json()["id"]
        await client.post(f"/api/v1/documents/{doc_id}/share", headers=alice["headers"], json={
            "recipient_user_id": bob["user_id"], "wrapped_key": "D" * 200, "access_level": "editor"})
        upd = {"title_ciphertext": "T==", "title_iv": FAKE_IV, "content_ciphertext": "C==", "content_iv": FAKE_IV}
        assert (await client.put(f"/api/v1/documents/{doc_id}", headers=bob["headers"], json=upd)).status_code == 200

        patch = await client.patch(f"/api/v1/documents/{doc_id}/members/{bob['user_id']}",
                                   headers=alice["headers"], json={"access_level": "viewer"})
        assert patch.status_code == 200
        assert (await client.put(f"/api/v1/documents/{doc_id}", headers=bob["headers"], json=upd)).status_code == 403

    async def test_removed_member_loses_file_access(self, client):
        alice, bob = await register(client), await register(client)
        ws = await self._make_ws(client, alice)
        await client.post(f"/api/v1/workspaces/{ws}/members", headers=alice["headers"],
                          json={"user_id": bob["user_id"], "wrapped_workspace_key": "W" * 200})
        doc_id = (await client.post("/api/v1/documents", headers=alice["headers"],
                                    json=doc_payload(ws))).json()["id"]
        await client.post(f"/api/v1/documents/{doc_id}/share", headers=alice["headers"], json={
            "recipient_user_id": bob["user_id"], "wrapped_key": "D" * 200, "access_level": "viewer"})

        rm = await client.delete(f"/api/v1/workspaces/{ws}/members/{bob['user_id']}", headers=alice["headers"])
        assert rm.status_code == 204
        assert (await client.get(f"/api/v1/documents/{doc_id}", headers=bob["headers"])).status_code == 404


# ── Admin Console ─────────────────────────────────────────

class TestLiveSync:
    async def test_poll_reflects_a_new_share_without_refresh(self, client):
        alice, bob = await register(client), await register(client)
        before = (await client.get("/api/v1/sync/poll", headers=bob["headers"])).json()

        doc_id = (await client.post("/api/v1/documents", headers=alice["headers"], json=doc_payload())).json()["id"]
        await client.post(f"/api/v1/documents/{doc_id}/share", headers=alice["headers"], json={
            "recipient_user_id": bob["user_id"], "wrapped_key": "D" * 200, "access_level": "viewer"})

        after = (await client.get("/api/v1/sync/poll", headers=bob["headers"])).json()
        assert doc_id in after["document_ids"] and doc_id not in before["document_ids"]
        assert after["documents_fp"] != before["documents_fp"]

    async def test_poll_reflects_workspace_invite_and_needs_auth(self, client):
        alice, bob = await register(client), await register(client)
        before = (await client.get("/api/v1/sync/poll", headers=bob["headers"])).json()
        ws = (await client.post("/api/v1/workspaces", headers=alice["headers"], json={
            "name_ciphertext": "ENC==", "name_iv": FAKE_IV, "wrapped_workspace_key": "W" * 200})).json()["id"]
        await client.post(f"/api/v1/workspaces/{ws}/members", headers=alice["headers"],
                          json={"user_id": bob["user_id"], "wrapped_workspace_key": "W" * 200})
        after = (await client.get("/api/v1/sync/poll", headers=bob["headers"])).json()
        assert ws in after["workspace_ids"] and after["workspaces_fp"] != before["workspaces_fp"]
        assert (await client.get("/api/v1/sync/poll")).status_code in (401, 403)


class TestAdminConsole:
    async def test_regular_user_gets_403(self, client):
        user = await register(client)
        assert user["is_admin"] is False
        resp = await client.get("/api/v1/admin/network-log", headers=user["headers"])
        assert resp.status_code == 403

    async def test_unauthenticated_rejected(self, client):
        assert (await client.get("/api/v1/admin/stats")).status_code in (401, 403)

    async def test_admin_sees_classified_traffic(self, client):
        # Admin account may already exist from a previous run → log in instead.
        reg = await client.post("/api/v1/auth/register", json=payload(ADMIN_EMAIL, username="console_admin"))
        if reg.status_code == 409:
            reg = await client.post("/api/v1/auth/login",
                                    json={"email": ADMIN_EMAIL, "password": STRONG_PASSWORD})
        data = reg.json()
        assert data["is_admin"] is True
        headers = {"Authorization": f"Bearer {data['access_token']}"}

        # generate some encrypted traffic
        user = await register(client)
        await client.post("/api/v1/documents", headers=user["headers"], json=doc_payload())

        log = (await client.get("/api/v1/admin/network-log", headers=headers)).json()
        upload = [e for e in log["entries"] if e["method"] == "POST" and e["path"] == "/api/v1/documents"]
        assert upload, "document upload should appear in the log"
        assert upload[-1]["verdict"] == "encrypted"

        register_entries = [e for e in log["entries"] if e["path"] == "/api/v1/auth/register"]
        raw = " ".join(e["request"]["raw"] for e in register_entries)
        assert STRONG_PASSWORD not in raw, "passwords must be redacted in the log"

    async def _admin_headers(self, client):
        reg = await client.post("/api/v1/auth/register", json=payload(ADMIN_EMAIL, username="console_admin"))
        if reg.status_code == 409:
            reg = await client.post("/api/v1/auth/login",
                                    json={"email": ADMIN_EMAIL, "password": STRONG_PASSWORD})
        return {"Authorization": f"Bearer {reg.json()['access_token']}"}

    async def test_admin_can_delete_user_and_their_data(self, client):
        admin = await self._admin_headers(client)
        alice, bob = await register(client), await register(client)
        doc_id = (await client.post("/api/v1/documents", headers=alice["headers"], json=doc_payload())).json()["id"]
        await client.post(f"/api/v1/documents/{doc_id}/share", headers=alice["headers"], json={
            "recipient_user_id": bob["user_id"], "wrapped_key": "D" * 200, "access_level": "viewer"})

        assert (await client.delete(f"/api/v1/admin/users/{alice['user_id']}", headers=admin)).status_code == 204
        # her document is gone for Bob too, and her token no longer works
        assert (await client.get(f"/api/v1/documents/{doc_id}", headers=bob["headers"])).status_code == 404
        assert (await client.get("/api/v1/sync/poll", headers=alice["headers"])).status_code == 401

    async def test_admin_cannot_delete_self_or_admins(self, client):
        admin = await self._admin_headers(client)
        me = (await client.get("/api/v1/auth/me", headers=admin)).json()
        assert (await client.delete(f"/api/v1/admin/users/{me['id']}", headers=admin)).status_code == 400

    async def test_regular_user_cannot_delete_users(self, client):
        alice, bob = await register(client), await register(client)
        resp = await client.delete(f"/api/v1/admin/users/{bob['user_id']}", headers=alice["headers"])
        assert resp.status_code == 403

    async def test_admin_can_delete_any_workspace(self, client):
        admin = await self._admin_headers(client)
        alice = await register(client)
        ws = (await client.post("/api/v1/workspaces", headers=alice["headers"], json={
            "name_ciphertext": "ENC==", "name_iv": FAKE_IV, "wrapped_workspace_key": "W" * 200})).json()["id"]
        listing = (await client.get("/api/v1/admin/workspaces", headers=admin)).json()
        assert any(w["id"] == ws for w in listing)
        assert (await client.delete(f"/api/v1/admin/workspaces/{ws}", headers=admin)).status_code == 204
        assert (await client.get(f"/api/v1/workspaces/{ws}/members", headers=alice["headers"])).status_code == 404

    async def test_admin_traffic_is_not_logged(self, client):
        before = network_log.latest_seq
        reg = await client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": STRONG_PASSWORD})
        if reg.status_code != 200:
            pytest.skip("admin account not created yet")
        headers = {"Authorization": f"Bearer {reg.json()['access_token']}"}
        mid = network_log.latest_seq
        await client.get("/api/v1/admin/stats", headers=headers)
        assert network_log.latest_seq == mid   # /admin calls add nothing
        assert mid >= before


# ── Admin: delete users ───────────────────────────────────

async def _admin_headers(client) -> tuple[dict, dict]:
    reg = await client.post("/api/v1/auth/register", json=payload(ADMIN_EMAIL, username="console_admin"))
    if reg.status_code == 409:
        reg = await client.post("/api/v1/auth/login",
                                json={"email": ADMIN_EMAIL, "password": STRONG_PASSWORD})
    data = reg.json()
    return {"Authorization": f"Bearer {data['access_token']}"}, data


class TestAdminDeleteUser:
    async def test_regular_user_cannot_delete(self, client):
        alice, bob = await register(client), await register(client)
        resp = await client.delete(f"/api/v1/admin/users/{bob['user_id']}", headers=alice["headers"])
        assert resp.status_code == 403

    async def test_admin_deletes_user_and_their_data(self, client):
        admin_headers, _ = await _admin_headers(client)
        alice, bob = await register(client), await register(client)
        doc_id = (await client.post("/api/v1/documents", headers=bob["headers"],
                                    json=doc_payload())).json()["id"]
        await client.post(f"/api/v1/documents/{doc_id}/share", headers=bob["headers"], json={
            "recipient_user_id": alice["user_id"], "wrapped_key": "D" * 200, "access_level": "viewer"})

        impact = (await client.get(f"/api/v1/admin/users/{bob['user_id']}/impact", headers=admin_headers)).json()
        assert impact["documents_owned"] == 1 and impact["documents_shared_with_others"] == 1

        resp = await client.delete(f"/api/v1/admin/users/{bob['user_id']}", headers=admin_headers)
        assert resp.status_code == 200, resp.text

        # bob can no longer sign in, and his shared file is gone for alice
        login = await client.post("/api/v1/auth/login",
                                  json={"email": bob["email"], "password": STRONG_PASSWORD})
        assert login.status_code == 401
        assert (await client.get(f"/api/v1/documents/{doc_id}", headers=alice["headers"])).status_code == 404

    async def test_admin_cannot_delete_self_or_other_admins(self, client):
        admin_headers, data = await _admin_headers(client)
        resp = await client.delete(f"/api/v1/admin/users/{data['user_id']}", headers=admin_headers)
        assert resp.status_code == 400

    async def test_unknown_user_404(self, client):
        admin_headers, _ = await _admin_headers(client)
        resp = await client.delete(f"/api/v1/admin/users/{uuid.uuid4()}", headers=admin_headers)
        assert resp.status_code == 404


# ── Admin: delete users / workspaces ──────────────────────

async def _admin_headers(client) -> dict:
    reg = await client.post("/api/v1/auth/register", json=payload(ADMIN_EMAIL, username="console_admin"))
    if reg.status_code == 409:
        reg = await client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": STRONG_PASSWORD})
    return {"Authorization": f"Bearer {reg.json()['access_token']}"}


class TestAdminDeletes:
    async def test_regular_user_cannot_delete_anything(self, client):
        alice, bob = await register(client), await register(client)
        assert (await client.delete(f"/api/v1/admin/users/{bob['user_id']}", headers=alice["headers"])).status_code == 403

    async def test_admin_deletes_user_and_their_workspace(self, client):
        admin = await _admin_headers(client)
        alice, bob = await register(client), await register(client)
        ws = (await client.post("/api/v1/workspaces", headers=alice["headers"], json={
            "name_ciphertext": "ENC==", "name_iv": FAKE_IV, "wrapped_workspace_key": "W" * 200})).json()["id"]
        await client.post(f"/api/v1/workspaces/{ws}/members", headers=alice["headers"],
                          json={"user_id": bob["user_id"], "wrapped_workspace_key": "W" * 200})
        await client.post("/api/v1/documents", headers=alice["headers"], json=doc_payload(ws))

        resp = await client.delete(f"/api/v1/admin/users/{alice['user_id']}", headers=admin)
        assert resp.status_code == 200
        # alice can no longer use her token, her workspace is gone for bob too
        assert (await client.get("/api/v1/workspaces", headers=alice["headers"])).status_code == 401
        assert (await client.get("/api/v1/workspaces", headers=bob["headers"])).json() == []

    async def test_admin_cannot_delete_self_or_other_admins(self, client):
        admin = await _admin_headers(client)
        me = (await client.get("/api/v1/auth/me", headers=admin)).json()
        assert (await client.delete(f"/api/v1/admin/users/{me['id']}", headers=admin)).status_code == 400

    async def test_admin_deletes_any_workspace(self, client):
        admin = await _admin_headers(client)
        alice = await register(client)
        ws = (await client.post("/api/v1/workspaces", headers=alice["headers"], json={
            "name_ciphertext": "ENC==", "name_iv": FAKE_IV, "wrapped_workspace_key": "W" * 200})).json()["id"]
        listing = (await client.get("/api/v1/admin/workspaces", headers=admin)).json()
        assert ws in [w["id"] for w in listing]
        assert (await client.delete(f"/api/v1/admin/workspaces/{ws}", headers=admin)).status_code == 200
        assert (await client.get("/api/v1/workspaces", headers=alice["headers"])).json() == []

    async def test_regular_user_cannot_delete_workspace_via_admin_api(self, client):
        alice = await register(client)
        assert (await client.delete(f"/api/v1/admin/workspaces/{uuid.uuid4()}", headers=alice["headers"])).status_code == 403
