from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json

import pytest

from wbcz.control_engine import decide
from wbcz.event_store import EventStore
from wbcz.models import Decision, KiState, Operation
from wbcz_ui.application import UiApplication
from wbcz_ui.live_true_api import (
    AuthSession,
    JsonlLiveAudit,
    LiveReadOnlyConfig,
    LiveTrueApiClient,
    ProductionMutationDisabled,
    PRODUCTION_BASE_URL,
    ReadOnlyTrueApiTransport,
    TrueApiAuthenticator,
    TrueApiCisesInfoAdapter,
    TrueApiProtocolError,
    WindowsCryptoProAuthSigner,
)

OWN = "1234567890"


def lp(status: str, **kwargs) -> KiState:
    return KiState(
        status,
        ownerInn=kwargs.pop("ownerInn", OWN),
        productGroup=kwargs.pop("productGroup", "lp"),
        **kwargs,
    )


def test_sale_introduced_with_receipt_ready(event):
    outcome = decide(event, lp("IN_CIRCULATION"), OWN)
    assert (outcome.decision, outcome.reason) == (
        Decision.READY_TO_WITHDRAW,
        "SALE_IN_CIRCULATION",
    )


def test_sale_introduced_without_receipt_manual(event):
    missing = replace(event, receipt_number=None, occurred_at=None)
    outcome = decide(missing, lp("IN_CIRCULATION"), OWN)
    assert (outcome.decision, outcome.reason) == (
        Decision.MANUAL_REVIEW,
        "SALE_RECEIPT_MISSING",
    )


def test_sale_withdrawn_remote_is_already_done_without_receipt(event):
    missing = replace(event, receipt_number=None, occurred_at=None)
    outcome = decide(
        missing,
        lp("WITHDRAWN", withdrawReason="DISTANCE"),
        OWN,
    )
    assert outcome.decision is Decision.ALREADY_DONE


def test_return_introduced_is_already_done_without_receipt(event):
    missing = replace(
        event,
        operation=Operation.RETURN,
        receipt_number=None,
        occurred_at=None,
    )
    outcome = decide(missing, lp("IN_CIRCULATION"), OWN)
    assert outcome.decision is Decision.ALREADY_DONE


def test_return_withdrawn_remote_with_receipt_ready(event):
    returned = replace(event, operation=Operation.RETURN)
    outcome = decide(
        returned,
        lp("WITHDRAWN", withdrawReason="DISTANCE"),
        OWN,
    )
    assert (outcome.decision, outcome.reason) == (
        Decision.READY_TO_RETURN,
        "RETURN_WITHDRAWN_DISTANCE",
    )


def test_return_withdrawn_remote_without_receipt_ready(event):
    returned = replace(
        event,
        operation=Operation.RETURN,
        receipt_number=None,
        occurred_at=None,
    )
    outcome = decide(
        returned,
        lp("WITHDRAWN", withdrawReason="DISTANCE"),
        OWN,
    )
    assert (outcome.decision, outcome.reason) == (
        Decision.READY_TO_RETURN,
        "RETURN_WITHDRAWN_DISTANCE",
    )


def test_owner_mismatch_manual(event):
    outcome = decide(
        event,
        lp("IN_CIRCULATION", ownerInn="9876543210"),
        OWN,
    )
    assert (outcome.decision, outcome.reason) == (
        Decision.MANUAL_REVIEW,
        "OWNER_MISMATCH",
    )


def test_unknown_true_api_status_manual(event):
    outcome = decide(event, lp("UNKNOWN:FUTURE"), OWN)
    assert (outcome.decision, outcome.reason) == (
        Decision.MANUAL_REVIEW,
        "UNKNOWN_CHZ_STATUS",
    )


def test_wrong_product_group_manual(event):
    outcome = decide(
        event,
        lp("IN_CIRCULATION", productGroup="milk"),
        OWN,
    )
    assert (outcome.decision, outcome.reason) == (
        Decision.MANUAL_REVIEW,
        "WRONG_PRODUCT_GROUP",
    )


def test_cises_info_adapter_mapping(event):
    adapter = TrueApiCisesInfoAdapter()
    state = adapter.normalize(
        event.kiz,
        {
            "cisInfo": {
                "requestedCis": event.kiz,
                "status": "INTRODUCED",
                "statusEx": "EMPTY",
                "withdrawReason": None,
                "ownerInn": OWN,
                "productGroup": "lp",
            }
        },
    )
    assert state == KiState(
        "IN_CIRCULATION",
        None,
        None,
        OWN,
        "lp",
    )


def test_cises_info_unknown_status_ex_never_optimistic(event):
    adapter = TrueApiCisesInfoAdapter()
    state = adapter.normalize(
        event.kiz,
        {
            "cisInfo": {
                "requestedCis": event.kiz,
                "status": "INTRODUCED",
                "statusEx": "FUTURE",
                "ownerInn": OWN,
                "productGroup": "lp",
            }
        },
    )
    outcome = decide(event, state, OWN)
    assert (outcome.decision, outcome.reason) == (
        Decision.MANUAL_REVIEW,
        "UNKNOWN_CHZ_STATUS",
    )


def test_cises_info_missing_critical_owner_is_manual(event):
    adapter = TrueApiCisesInfoAdapter()
    state = adapter.normalize(
        event.kiz,
        {
            "cisInfo": {
                "requestedCis": event.kiz,
                "status": "INTRODUCED",
                "statusEx": "EMPTY",
            }
        },
    )
    outcome = decide(event, state, OWN)
    assert (outcome.decision, outcome.reason) == (
        Decision.MANUAL_REVIEW,
        "OWNER_UNKNOWN",
    )


def test_cises_info_unexpected_schema_is_protocol_error(event):
    adapter = TrueApiCisesInfoAdapter()
    with pytest.raises(TrueApiProtocolError):
        adapter.normalize(event.kiz, {"cisInfo": "not-an-object"})


class FakeAuth:
    def __init__(self):
        self.calls = 0

    def authenticate(self):
        self.calls += 1
        return AuthSession(
            "secret-token",
            datetime.now(timezone.utc) + timedelta(hours=1),
        )


class FakeTransport:
    def __init__(self):
        self.calls = []

    def request_json(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        batch = kwargs["body"]
        return [
            {
                "cisInfo": {
                    "requestedCis": kiz,
                    "status": "INTRODUCED",
                    "statusEx": "EMPTY",
                    "ownerInn": OWN,
                    "productGroup": "lp",
                }
            }
            for kiz in batch
        ]


def test_cises_info_safe_batching():
    transport = FakeTransport()
    auth = FakeAuth()
    client = LiveTrueApiClient(
        transport,
        auth,
        batch_limit=2,
        max_requests_per_second=50,
    )
    # This test starts after the explicit authentication step; priming itself
    # must never manufacture or refresh a production session implicitly.
    client._session = auth.authenticate()
    client.prime(["K1", "K2", "K3", "K4", "K5"])
    assert auth.calls == 1
    assert [len(call[2]["body"]) for call in transport.calls] == [2, 2, 1]
    assert [call[2]["body"] for call in transport.calls] == [
        ["K1", "K2"],
        ["K3", "K4"],
        ["K5"],
    ]
    assert all(
        call[1] == "/cises/info"
        and call[2]["params"] == {"pg": "lp"}
        for call in transport.calls
    )
    assert client.get_ki_state("K5").status == "IN_CIRCULATION"


class AuthTransport:
    def __init__(self):
        self.calls = []

    def request_json(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        if path == "/auth/key":
            return {"uuid": "u", "data": "challenge"}
        return {
            "uuidToken": "tok",
            "expireDate": "2099-01-01T00:00:00Z",
        }


class AuthOnlySigner:
    def __init__(self):
        self.payloads = []

    def sign_auth_challenge(self, data):
        self.payloads.append(data)
        return "cms-base64"


def test_auth_signing_is_separate_from_document_signing():
    transport = AuthTransport()
    signer = AuthOnlySigner()
    session = TrueApiAuthenticator(
        transport,
        signer,
        OWN,
    ).authenticate()
    assert session.bearer_token == "tok"
    assert signer.payloads == ["challenge"]
    body = transport.calls[1][2]["body"]
    assert body == {
        "uuid": "u",
        "data": "cms-base64",
        "inn": OWN,
        "unitedToken": True,
    }
    production_signer = WindowsCryptoProAuthSigner("AA11")
    for forbidden_name in (
        "sign_document",
        "sign_payload_for_submission",
        "submit_signed_document",
        "sign",
    ):
        assert not hasattr(production_signer, forbidden_name)


def test_production_mutation_endpoint_is_blocked_before_http(tmp_path):
    opener_calls = []

    def forbidden_opener(*args, **kwargs):
        opener_calls.append((args, kwargs))
        raise AssertionError("network opener must not be reached")

    transport = ReadOnlyTrueApiTransport(
        audit=JsonlLiveAudit(tmp_path / "audit.jsonl"),
        opener=forbidden_opener,
    )
    with pytest.raises(ProductionMutationDisabled):
        transport.request_json(
            "POST",
            "/lk/documents/create",
            body={"document": "forbidden"},
        )
    assert opener_calls == []

    for path in (
        "/lk/documents/cancel",
        "/lk/documents/retry",
        "/documents/LP_RETURN",
        "/documents/LK_RECEIPT",
    ):
        with pytest.raises(ProductionMutationDisabled):
            transport.request_json("POST", path, body={})
    assert opener_calls == []


def test_production_allowlist_is_exact():
    ReadOnlyTrueApiTransport.assert_allowed("GET", "/auth/key")
    ReadOnlyTrueApiTransport.assert_allowed(
        "POST", "/auth/simpleSignIn"
    )
    ReadOnlyTrueApiTransport.assert_allowed(
        "POST",
        "/cises/info",
        {"pg": "lp"},
    )
    with pytest.raises(ProductionMutationDisabled):
        ReadOnlyTrueApiTransport.assert_allowed(
            "POST",
            "/cises/info",
            {"pg": "shoes"},
        )
    with pytest.raises(ProductionMutationDisabled):
        ReadOnlyTrueApiTransport.assert_allowed(
            "GET",
            "/cises/info",
            {"pg": "lp"},
        )


def test_live_audit_contains_metadata_but_not_secret_fields(tmp_path):
    path = tmp_path / "live.jsonl"
    audit = JsonlLiveAudit(path)
    audit.record(
        method="POST",
        endpoint="/cises/info",
        cis_count=7,
        http_status=200,
        request_id="r-1",
    )
    row = json.loads(path.read_text(encoding="utf-8"))
    assert row["mode"] == "LIVE_READ_ONLY"
    assert row["endpoint"] == "/cises/info"
    assert row["cis_count"] == 7
    assert row["http_status"] == 200
    assert row["request_id"] == "r-1"
    forbidden = {
        "token",
        "signature",
        "private_key",
        "pin",
        "certificate",
    }
    assert forbidden.isdisjoint(row)


class AppLiveClient:
    def __init__(self):
        self.states = {}
        self.authenticated = True

    def prime(self, kizes):
        for kiz in kizes:
            self.states[kiz] = KiState(
                "IN_CIRCULATION",
                ownerInn=OWN,
                productGroup="lp",
            )

    def get_ki_state(self, kiz):
        return self.states[kiz]


def test_live_read_only_check_creates_no_production_documents(
    tmp_path,
    wb_row,
    make_xlsx,
):
    source = make_xlsx([wb_row], "live.xlsx")
    config = LiveReadOnlyConfig(
        True,
        OWN,
        "THUMB",
        PRODUCTION_BASE_URL,
        tmp_path / "live.jsonl",
    )
    client = AppLiveClient()
    app = UiApplication(
        tmp_path / "live.sqlite",
        config,
        lambda _: client,
    )
    imported = app.import_bytes(
        source.name,
        source.read_bytes(),
    )
    event_id = app.events_for_import(
        imported["fingerprint"]
    )[0]["event_id"]
    result = app.check_import(
        imported["fingerprint"],
        [event_id],
    )
    assert result["provider"] == "live-read-only"
    assert result["counts"] == {"READY_TO_WITHDRAW": 1}
    with EventStore(app.db_path) as store:
        assert store.count("documents") == 0
        assert store.count("document_status_history") == 0
