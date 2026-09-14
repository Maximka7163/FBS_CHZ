from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import base64
import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from wbcz.models import Decision
from wbcz.p0_write import (
    CertificateMetadata,
    P0WritePipeline,
    SigningResponse,
    WriteState,
)
from wbcz_web.models import Base, EventRecord
from wbcz_web.repositories.write_pipeline import SqlWritePipelineStore


DB_URL = os.getenv("WBCZ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL, reason="WBCZ_TEST_DATABASE_URL requires PostgreSQL")


def test_sql_store_persists_signing_state_and_audit_with_unique_business_operation():
    engine = create_engine(DB_URL, future=True)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    event_id = "f" * 64
    try:
        with factory() as db:
            db.add(
                EventRecord(
                    event_id=event_id,
                    kiz="TEST-CIS-PERSISTENCE",
                    task_number="1",
                    sticker="2",
                    operation="Продажа",
                    occurred_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
                    receipt_number="3",
                    fiscal_drive_number="4",
                    amount=Decimal("100.00"),
                    currency="RUB",
                    legal_entity_sale=False,
                    payload={"test": True},
                )
            )
            db.commit()

        with factory() as db:
            pipeline = P0WritePipeline(SqlWritePipelineStore(db))
            operation = pipeline.prepare(
                source_event_id=event_id,
                decision=Decision.READY_TO_WITHDRAW,
                operation_reason="DISTANCE",
                expected_inn="1234567890",
                document_body={"document_number": "PERSIST-1"},
            )
            repeat = pipeline.prepare(
                source_event_id=event_id,
                decision=Decision.READY_TO_WITHDRAW,
                operation_reason="DISTANCE",
                expected_inn="1234567890",
                document_body={"document_number": "PERSIST-1"},
            )
            assert repeat.operation_id == operation.operation_id
            request = pipeline.create_signing_request(operation.operation_id)
            signed = pipeline.accept_signature(
                SigningResponse(
                    operation_id=operation.operation_id,
                    document_sha256=request.document_sha256,
                    signature_base64=base64.b64encode(b"detached-signature").decode("ascii"),
                    certificate=CertificateMetadata(certificate_inn="1234567890"),
                )
            )
            assert signed.state is WriteState.SIGNED
            db.commit()
            operation_id = operation.operation_id

        with factory() as db:
            store = SqlWritePipelineStore(db)
            restored = store.get_operation(operation_id)
            assert restored is not None
            assert restored.state is WriteState.SIGNED
            assert restored.document_sha256
            assert restored.signature_base64
            audit = store.audit_for_operation(operation_id)
            assert [entry.to_state for entry in audit] == [
                "PREPARED",
                "AWAITING_SIGNATURE",
                "SIGNED",
            ]
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
