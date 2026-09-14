from __future__ import annotations

import base64
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import json

import pytest

from wbcz.agent_true_api_transport import ProductionAgentTrueApiTransport
from wbcz.document_assembler import (
    ABSENT,
    DocumentAssemblyManualReview,
    OfficialP0DocumentAssembler,
    OrganisationType,
    P0OrganisationConfig,
    ReturnPrimaryDocument,
    rubles_to_kopecks,
    schema_object,
)
from wbcz.models import Decision, Event, Operation, canonical_json
from wbcz.windows_agent import AgentSecurityError
from wbcz_web.config import WebConfig
from wbcz_ui.live_true_api import TrueApiCisesInfoAdapter, TrueApiError


OWN = "1234567890"
IP_INN = "123456789012"
FIAS = "11111111-2222-3333-4444-555555555555"
KPP = "123456789"
CIS = "0102900897077810215Pph%ybnsRtdA"
CIS2 = "0102900897078091215s<ESP8kc)NQB"


def event(
    operation: Operation = Operation.SALE,
    *,
    amount: Decimal = Decimal("1901.75"),
    currency: str = "RUB",
    cis: str = CIS,
) -> Event:
    return Event(
        kiz=cis,
        task_number="5474747096",
        sticker="56718292969",
        operation=operation,
        occurred_at=datetime(2026, 8, 19, 4, 58, tzinfo=timezone(timedelta(hours=5))),
        receipt_number="211671",
        fiscal_drive_number="7380440903834317",
        amount=amount,
        currency=currency,
        legal_entity_sale=False,
    )


def legal(*, paid: bool | None = False) -> P0OrganisationConfig:
    return P0OrganisationConfig(
        participant_inn=OWN,
        organisation_type=OrganisationType.LEGAL_ENTITY,
        fias_id=FIAS,
        kpp=KPP,
        remote_sale_return_paid=paid,
    )


def ip(*, paid: bool | None = False) -> P0OrganisationConfig:
    return P0OrganisationConfig(
        participant_inn=IP_INN,
        organisation_type=OrganisationType.INDIVIDUAL_ENTREPRENEUR,
        fias_id=FIAS,
        kpp=None,
        remote_sale_return_paid=paid,
    )


class FakeTunnel:
    local_port = 17654

    def session_marker(self):
        return 0

    def assert_gost_session(self, marker):
        assert marker == 0

    def diagnostics(self):
        return {"gost_session_verified": True}


class FakeAudit:
    def record(self, **kwargs):
        pass


class FakeResponse:
    status = 200
    headers = {}

    def read(self):
        return b"[]"


class CaptureConnection:
    captured: dict[str, object] = {}

    def __init__(self, *args, **kwargs):
        pass

    def putrequest(self, method, target, skip_host=False):
        self.captured["method"] = method
        self.captured["target"] = target

    def putheader(self, name, value):
        self.captured.setdefault("headers", {})[name] = value

    def endheaders(self, data=None):
        self.captured["body"] = data

    def getresponse(self):
        return FakeResponse()

    def close(self):
        pass


def test_cises_info_exact_wire_body_is_root_json_array():
    CaptureConnection.captured = {}
    transport = ProductionAgentTrueApiTransport(
        tunnel=FakeTunnel(),
        audit=FakeAudit(),
        connection_factory=CaptureConnection,
    )
    transport.cises_info((CIS, CIS2), bearer_token="memory-token")
    assert CaptureConnection.captured["target"] == "/api/v3/true-api/cises/info?pg=lp"
    assert CaptureConnection.captured["body"] == (
        '["' + CIS + '","' + CIS2.replace('\\', '\\\\').replace('"', '\\"') + '"]'
    ).encode("utf-8")
    assert json.loads(CaptureConnection.captured["body"]) == [CIS, CIS2]
    assert not CaptureConnection.captured["body"].startswith(b"{")
    assert b'"cis":' not in CaptureConnection.captured["body"]


def test_cises_info_rejects_more_than_1000_and_invalid_cis_before_network():
    transport = ProductionAgentTrueApiTransport(
        tunnel=FakeTunnel(),
        audit=FakeAudit(),
        connection_factory=CaptureConnection,
    )
    with pytest.raises(AgentSecurityError, match="1..1000"):
        transport.cises_info((CIS,) * 1001, bearer_token="memory-token")
    with pytest.raises(AgentSecurityError, match="18..74"):
        transport.cises_info(("short",), bearer_token="memory-token")


def test_cises_info_individual_nested_error_is_not_batch_success():
    adapter = TrueApiCisesInfoAdapter()
    ok = adapter.normalize(
        CIS,
        {
            "cisInfo": {
                "requestedCis": CIS,
                "status": "INTRODUCED",
                "ownerInn": OWN,
                "productGroup": "lp",
            }
        },
    )
    assert ok.ownerInn == OWN
    with pytest.raises(TrueApiError, match="cisInfo"):
        adapter.normalize(
            CIS2,
            {
                "cisInfo": {
                    "requestedCis": CIS2,
                    "errorCode": "INVALID_CIS",
                    "errorMessage": "bad item",
                }
            },
        )


def test_lk_receipt_distance_exact_minimal_legal_entity_json():
    document = OfficialP0DocumentAssembler(legal()).build_exact(
        event(), Decision.READY_TO_WITHDRAW
    )
    expected = {
        "inn": OWN,
        "action": "DISTANCE",
        "action_date": "2026-08-19",
        "fias_id": FIAS,
        "kpp": KPP,
        "products": [{"cis": CIS, "product_cost": 190175}],
    }
    assert document.payload == canonical_json(expected).encode("utf-8")
    payload = json.loads(document.payload)
    assert payload == expected
    assert payload["action"] == "DISTANCE"
    assert type(payload["products"][0]["product_cost"]) is int
    assert "buyer_inn" not in payload
    for forbidden in (
        "document_type",
        "document_number",
        "document_date",
        "primary_document_type",
        "primary_document_number",
        "primary_document_date",
        "receipt_number",
        "fiscal_drive_number",
    ):
        assert forbidden not in payload


def test_lk_receipt_ip_requires_fias_and_omits_kpp():
    document = OfficialP0DocumentAssembler(ip()).build_exact(
        event(), Decision.READY_TO_WITHDRAW
    )
    payload = json.loads(document.payload)
    assert payload["inn"] == IP_INN
    assert payload["fias_id"] == FIAS
    assert "kpp" not in payload


def test_organisation_location_is_explicit_and_fails_closed():
    with pytest.raises(ValueError, match="kpp"):
        P0OrganisationConfig(
            participant_inn=OWN,
            organisation_type=OrganisationType.LEGAL_ENTITY,
            fias_id=FIAS,
            kpp=None,
        )
    with pytest.raises(ValueError, match="must not configure kpp"):
        P0OrganisationConfig(
            participant_inn=IP_INN,
            organisation_type=OrganisationType.INDIVIDUAL_ENTREPRENEUR,
            fias_id=FIAS,
            kpp=KPP,
        )
    with pytest.raises(DocumentAssemblyManualReview, match="ORGANISATION_CONFIG_MISSING"):
        OfficialP0DocumentAssembler(None).build_exact(event(), Decision.READY_TO_WITHDRAW)


def test_money_mapping_uses_decimal_not_binary_float_rounding():
    assert rubles_to_kopecks(Decimal("0.01")) == 1
    assert rubles_to_kopecks(Decimal("1901.75")) == 190175
    assert rubles_to_kopecks(Decimal("2265.99")) == 226599
    with pytest.raises(DocumentAssemblyManualReview, match="SUBKOPECK"):
        rubles_to_kopecks(Decimal("1.001"))
    with pytest.raises(DocumentAssemblyManualReview, match="INVALID"):
        rubles_to_kopecks(1.1)  # type: ignore[arg-type]


def test_lk_receipt_unsupported_currency_fails_closed_no_fx():
    with pytest.raises(DocumentAssemblyManualReview, match="UNSUPPORTED_CURRENCY"):
        OfficialP0DocumentAssembler(legal()).build_exact(
            event(currency="USD"), Decision.READY_TO_WITHDRAW
        )


def test_lp_return_paid_false_exact_json_and_no_invented_permits_or_primary_doc():
    document = OfficialP0DocumentAssembler(legal(paid=False)).build_exact(
        event(Operation.RETURN), Decision.READY_TO_RETURN
    )
    expected = {
        "trade_participant_inn": OWN,
        "return_type": "REMOTE_SALE_RETURN",
        "paid": False,
        "products_list": [{"ki": CIS}],
    }
    assert document.payload == canonical_json(expected).encode("utf-8")
    payload = json.loads(document.payload)
    assert payload == expected
    for forbidden in (
        "primary_document_type",
        "primary_document_number",
        "primary_document_date",
        "primary_document_custom_name",
        "certificate_type",
        "certificate_number",
        "certificate_date",
    ):
        assert forbidden not in payload


def test_lp_return_paid_has_no_default_and_paid_true_requires_explicit_primary_source():
    with pytest.raises(DocumentAssemblyManualReview, match="PAID_REQUIRED"):
        OfficialP0DocumentAssembler(legal(paid=None)).build_exact(
            event(Operation.RETURN), Decision.READY_TO_RETURN
        )
    # WB receipt/FN are present in the event, but are not silently mapped.
    with pytest.raises(DocumentAssemblyManualReview, match="PRIMARY_DOCUMENT_REQUIRED"):
        OfficialP0DocumentAssembler(legal(paid=True)).build_exact(
            event(Operation.RETURN), Decision.READY_TO_RETURN
        )


def test_lp_return_paid_true_exact_document_level_primary_document():
    primary = ReturnPrimaryDocument(
        document_type="RECEIPT",
        number="R-2026-0001",
        document_date=date(2026, 8, 19),
    )
    document = OfficialP0DocumentAssembler(
        legal(paid=True), primary_document_provider=lambda _: primary
    ).build_exact(event(Operation.RETURN), Decision.READY_TO_RETURN)
    expected = {
        "trade_participant_inn": OWN,
        "return_type": "REMOTE_SALE_RETURN",
        "paid": True,
        "primary_document_type": "RECEIPT",
        "primary_document_number": "R-2026-0001",
        "primary_document_date": "2026-08-19",
        "products_list": [{"ki": CIS}],
    }
    assert document.payload == canonical_json(expected).encode("utf-8")
    payload = json.loads(document.payload)
    assert payload == expected
    assert "primary_document_custom_name" not in payload


def test_lp_return_other_primary_document_requires_custom_name_and_forbids_it_otherwise():
    with pytest.raises(DocumentAssemblyManualReview, match="CUSTOM_NAME_REQUIRED"):
        ReturnPrimaryDocument("OTHER", "1", date(2026, 8, 19)).fields()
    with pytest.raises(DocumentAssemblyManualReview, match="CUSTOM_NAME_FORBIDDEN"):
        ReturnPrimaryDocument("RECEIPT", "1", date(2026, 8, 19), "not allowed").fields()
    assert ReturnPrimaryDocument("OTHER", "1", date(2026, 8, 19), "Акт").fields()[
        "primary_document_custom_name"
    ] == "Акт"


def test_optional_null_policy_distinguishes_explicit_null_from_absent():
    value = schema_object({"optional_null": None, "forbidden": ABSENT, "required": "x"})
    assert "optional_null" in value and value["optional_null"] is None
    assert "forbidden" not in value
    assert canonical_json(value) == '{"optional_null":null,"required":"x"}'


def test_exact_bytes_hash_base64_and_signing_bytes_invariant():
    for assembler, ev, decision in (
        (OfficialP0DocumentAssembler(legal()), event(), Decision.READY_TO_WITHDRAW),
        (OfficialP0DocumentAssembler(legal(paid=False)), event(Operation.RETURN), Decision.READY_TO_RETURN),
    ):
        document = assembler.build_exact(ev, decision)
        decoded = base64.b64decode(document.product_document_base64, validate=True)
        assert decoded == document.bytes_for_signature == document.payload
        assert hashlib.sha256(decoded).hexdigest() == document.sha256


@pytest.mark.parametrize(
    "decision",
    [Decision.MANUAL_REVIEW, Decision.ERROR, Decision.ALREADY_DONE, Decision.NO_ACTION],
)
def test_non_ready_control_decisions_cannot_invoke_business_assembly(decision):
    with pytest.raises(DocumentAssemblyManualReview, match="CONTROL_DECISION_NOT_WRITABLE"):
        OfficialP0DocumentAssembler(legal()).build_exact(event(), decision)


def test_web_config_validates_partial_organisation_config_fail_closed():
    base = dict(
        database_url="postgresql+psycopg://u:p@db:5432/wbcz",
        own_inn=OWN,
        environment="test",
    )
    with pytest.raises(ValueError, match="FIAS"):
        WebConfig(**base, organisation_type=OrganisationType.LEGAL_ENTITY).validate_for_startup()
    with pytest.raises(ValueError, match="ORGANISATION_TYPE"):
        WebConfig(**base, activity_fias_id=FIAS).validate_for_startup()
