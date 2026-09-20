from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Mapping


_ID = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_KEYS = frozenset({
    "full_km", "fullkm", "km", "payload", "raw_payload", "zpl", "epl", "cpcl",
    "command", "command_bytes", "script", "path", "url", "printer_command",
})


class PrintAgentContractError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PrintAgentItemRef:
    print_job_item_id: str
    stored_full_km_item_id: str
    ordinal: int
    payload_sha256: str

    def validate(self) -> None:
        if not _ID.fullmatch(self.print_job_item_id) or not _ID.fullmatch(self.stored_full_km_item_id):
            raise PrintAgentContractError("invalid print item reference")
        if type(self.ordinal) is not int or not 0 <= self.ordinal <= 999:
            raise PrintAgentContractError("invalid print item ordinal")
        if not _SHA.fullmatch(self.payload_sha256):
            raise PrintAgentContractError("invalid payload hash")


@dataclass(frozen=True, slots=True)
class PrintAgentJobContract:
    contract_version: str
    job_id: str
    organisation_id: str
    participant_id: str
    template_version_id: str
    mode: str
    printer_profile_id: str | None
    printer_profile_fingerprint: str | None
    items: tuple[PrintAgentItemRef, ...]
    sensitive_payload_delivery: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PrintAgentJobContract":
        allowed = {
            "contract_version", "job_id", "organisation_id", "participant_id",
            "template_version_id", "mode", "printer_profile_id",
            "printer_profile_fingerprint", "items", "sensitive_payload_delivery",
        }
        unknown = set(value) - allowed
        if unknown:
            raise PrintAgentContractError(f"unsupported print-agent fields: {sorted(unknown)}")
        if any(str(key).casefold() in FORBIDDEN_KEYS for key in value):
            raise PrintAgentContractError("sensitive/arbitrary printer payload is forbidden")
        raw_items = value.get("items")
        if not isinstance(raw_items, list) or not 1 <= len(raw_items) <= 1000:
            raise PrintAgentContractError("print-agent items must contain 1..1000 refs")
        items: list[PrintAgentItemRef] = []
        for raw in raw_items:
            if not isinstance(raw, Mapping) or set(raw) != {
                "print_job_item_id", "stored_full_km_item_id", "ordinal", "payload_sha256"
            }:
                raise PrintAgentContractError("invalid print-agent item shape")
            item = PrintAgentItemRef(
                print_job_item_id=str(raw["print_job_item_id"]),
                stored_full_km_item_id=str(raw["stored_full_km_item_id"]),
                ordinal=raw["ordinal"],
                payload_sha256=str(raw["payload_sha256"]),
            )
            item.validate()
            items.append(item)
        result = cls(
            contract_version=str(value.get("contract_version") or ""),
            job_id=str(value.get("job_id") or ""),
            organisation_id=str(value.get("organisation_id") or ""),
            participant_id=str(value.get("participant_id") or ""),
            template_version_id=str(value.get("template_version_id") or ""),
            mode=str(value.get("mode") or ""),
            printer_profile_id=str(value["printer_profile_id"]) if value.get("printer_profile_id") is not None else None,
            printer_profile_fingerprint=str(value["printer_profile_fingerprint"]) if value.get("printer_profile_fingerprint") is not None else None,
            items=tuple(items),
            sensitive_payload_delivery=str(value.get("sensitive_payload_delivery") or ""),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if self.contract_version != "printing-agent-v1":
            raise PrintAgentContractError("unsupported print-agent contract version")
        for value in (self.job_id, self.organisation_id, self.participant_id, self.template_version_id):
            if not _ID.fullmatch(value):
                raise PrintAgentContractError("invalid print-agent id")
        if self.mode not in {"INITIAL_PRINT", "REPRINT_ORIGINAL_TEMPLATE", "PRINT_USING_CURRENT_TEMPLATE"}:
            raise PrintAgentContractError("invalid print mode")
        if self.printer_profile_id is not None and not _ID.fullmatch(self.printer_profile_id):
            raise PrintAgentContractError("invalid logical printer profile id")
        if self.printer_profile_fingerprint is not None and not _SHA.fullmatch(self.printer_profile_fingerprint):
            raise PrintAgentContractError("invalid printer profile fingerprint")
        if self.sensitive_payload_delivery != "BLOCKED_NOT_IMPLEMENTED":
            raise PrintAgentContractError("production-sensitive payload delivery is not accepted")
        ordinals = [item.ordinal for item in self.items]
        if ordinals != list(range(len(self.items))):
            raise PrintAgentContractError("print item ordinals must be contiguous")

    def canonical_sha256(self) -> str:
        data = {
            "contract_version": self.contract_version,
            "job_id": self.job_id,
            "organisation_id": self.organisation_id,
            "participant_id": self.participant_id,
            "template_version_id": self.template_version_id,
            "mode": self.mode,
            "printer_profile_id": self.printer_profile_id,
            "printer_profile_fingerprint": self.printer_profile_fingerprint,
            "items": [
                {
                    "print_job_item_id": x.print_job_item_id,
                    "stored_full_km_item_id": x.stored_full_km_item_id,
                    "ordinal": x.ordinal,
                    "payload_sha256": x.payload_sha256,
                }
                for x in self.items
            ],
            "sensitive_payload_delivery": self.sensitive_payload_delivery,
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class FakePrintExecutionResult:
    outcome: str
    contract_sha256: str
    physical_printer_called: bool
    sensitive_payload_received: bool
    safe_error_code: str | None = None


class FakePrintExecutor:
    """Contract validator only. It never receives FULL KM and never touches a printer."""

    def execute(self, value: Mapping[str, Any]) -> FakePrintExecutionResult:
        contract = PrintAgentJobContract.from_mapping(value)
        return FakePrintExecutionResult(
            outcome="BLOCKED",
            contract_sha256=contract.canonical_sha256(),
            physical_printer_called=False,
            sensitive_payload_received=False,
            safe_error_code="SENSITIVE_PAYLOAD_DELIVERY_NOT_IMPLEMENTED",
        )
