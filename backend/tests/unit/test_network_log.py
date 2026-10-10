# tests/unit/test_network_log.py
# The Admin Console classifier must (a) recognise real ciphertext and
# (b) shout when readable text shows up where ciphertext is expected.

import base64
import json
import os

from app.core.network_log import analyse_body, verdict_for, NetworkLogStore


def _b64(n: int) -> str:
    return base64.b64encode(os.urandom(n)).decode()


def _body(d: dict) -> bytes:
    return json.dumps(d).encode()


def test_encrypted_document_upload_is_classified_as_encrypted():
    req = analyse_body(_body({
        "title_ciphertext": _b64(60), "title_iv": "AAAAAAAAAAAAAAAA",
        "content_ciphertext": _b64(400), "content_iv": "AAAAAAAAAAAAAAAA",
        "wrapped_key_for_owner": _b64(256),
        "search_index": [{"keyword_token": "a" * 64}],
    }), "application/json")
    kinds = {f["key"]: f["kind"] for f in req["fields"]}
    assert kinds["content_ciphertext"] == "ciphertext"
    assert kinds["wrapped_key_for_owner"] == "wrapped_key"
    assert verdict_for(req, {"fields": []}) == "encrypted"


def test_high_entropy_reported_for_real_ciphertext():
    req = analyse_body(_body({"content_ciphertext": _b64(600)}), "application/json")
    assert req["fields"][0]["entropy"] > 7.0


def test_plaintext_in_ciphertext_field_raises_warning():
    req = analyse_body(_body({"content_ciphertext": "my secret meeting notes"}), "application/json")
    assert req["fields"][0]["kind"] == "PLAINTEXT?"
    assert verdict_for(req, {"fields": []}) == "warning"


def test_password_is_redacted_everywhere():
    req = analyse_body(_body({"email": "a@b.com", "password": "Sup3r!Secret#Pw"}), "application/json")
    assert "Sup3r" not in req["raw"]
    assert all("Sup3r" not in f["preview"] for f in req["fields"])
    assert verdict_for(req, {"fields": []}) == "auth"


def test_ring_buffer_and_since():
    store = NetworkLogStore(size=3)
    for i in range(5):
        store.add({"path": f"/{i}"})
    assert store.latest_seq == 5
    assert [e["path"] for e in store.since(0)] == ["/2", "/3", "/4"]
    assert [e["path"] for e in store.since(4)] == ["/4"]
