from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    s = p.read_text(encoding="utf-8")
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{path}: expected exactly one match, got {n}: {old[:120]!r}")
    p.write_text(s.replace(old, new, 1), encoding="utf-8")


p = "src/wbcz/aggregation.py"
replace_once(
    p,
    '''def _code(value: Any, label: str) -> str:\n    text = _text(value, label, max_len=74)\n    if not 18 <= len(text) <= 74 or any(ch.isspace() for ch in text):\n        raise AggregationContractError(f"{label} must be 18..74 non-whitespace chars")\n    return text\n\n\n''',
    '''def _code(value: Any, label: str) -> str:\n    # Generic CIS/KI validation intentionally remains separate from aggregate-id rules.\n    text = _text(value, label, max_len=74)\n    if not 18 <= len(text) <= 74 or any(ch.isspace() for ch in text):\n        raise AggregationContractError(f"{label} must be 18..74 non-whitespace chars")\n    return text\n\n\nAGGREGATE_IDENTIFIER_ALLOWED_CHARS = frozenset(\n    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789%&'\\\"()*+,_./:;<?!"\n)\n\n\ndef validate_aggregate_identifier(value: Any, label: str = "aggregate_identifier") -> str:\n    \"\"\"Validate official 18..74-char KIGU/KITU/KIN aggregate identifiers.\"\"\"\n    text = _text(value, label, max_len=74)\n    if not 18 <= len(text) <= 74:\n        raise AggregationContractError(f"{label} must be 18..74 chars")\n    if any(ch not in AGGREGATE_IDENTIFIER_ALLOWED_CHARS for ch in text):\n        raise AggregationContractError(f"{label} contains a character outside the official aggregate identifier set")\n    return text\n\n\n''',
)
replace_once(p, '        parent = _code(self.unit_serial_number, "unitSerialNumber")\n', '        parent = validate_aggregate_identifier(self.unit_serial_number, "unitSerialNumber")\n')
replace_once(p, '        return {"unitSerialNumber": _code(self.unit_serial_number, "unitSerialNumber"), "sntins": list(children)}\n', '        return {"unitSerialNumber": validate_aggregate_identifier(self.unit_serial_number, "unitSerialNumber"), "sntins": list(children)}\n')
replace_once(p, '        return {"uit_uitu": _code(self.uit_uitu, "uit_uitu")} if self.uit_uitu is not None else {"kitu": _code(self.kitu, "kitu")}\n', '        return {"uit_uitu": _code(self.uit_uitu, "uit_uitu")} if self.uit_uitu is not None else {"kitu": validate_aggregate_identifier(self.kitu, "kitu")}\n')
replace_once(p, '        return {"participant_inn": _inn(self.participant_inn, "participant_inn"), "reaggregation_type": kind, "uitu": _code(self.uitu, "uitu"), "uit_uitu_list": items}\n', '        return {"participant_inn": _inn(self.participant_inn, "participant_inn"), "reaggregation_type": kind, "uitu": validate_aggregate_identifier(self.uitu, "uitu"), "uit_uitu_list": items}\n')
replace_once(p, '        codes = tuple(_code(x, "products_list[].uitu") for x in self.products_list)\n', '        codes = tuple(validate_aggregate_identifier(x, "products_list[].uitu") for x in self.products_list)\n')

s = Path(p).read_text(encoding="utf-8")
start = s.index("def validate_box_preconditions(")
end = s.index("\n\ndef validate_reaggregation_preconditions(", start)
box_func = '''def validate_box_preconditions(\n    *,\n    parent: CisAggregationSnapshot | None,\n    children: Sequence[CisAggregationSnapshot],\n    participant_inn: str,\n    leading_pg: str = M6_PG,\n    mixed_pg: bool = False,\n    runtime_formed_status_values: frozenset[str] = frozenset(),\n) -> None:\n    owner = _inn(participant_inn, "participant_inn")\n    if parent is not None:\n        raise AggregationManualReview("KITU_PARENT_IDENTIFIER_ALREADY_PRESENT_IN_CRPT")\n    if not children:\n        raise AggregationContractError("KITU children required")\n\n    if mixed_pg:\n        for child in children:\n            if child.status_raw != "INTRODUCED" and child.status_raw not in runtime_formed_status_values:\n                raise AggregationManualReview("MULTIPRODUCT_KITU_CHILD_STATUS_NOT_CONFIRMED")\n            if child.status_ex_raw not in (None, "", "WAIT_TRANSFER_TO_OWNER"):\n                raise AggregationManualReview("MULTIPRODUCT_KITU_CHILD_STATUS_EX_NOT_SUPPORTED")\n    else:\n        statuses = {x.status_raw for x in children}\n        if len(statuses) != 1:\n            raise AggregationManualReview("KITU_CHILD_STATUSES_MUST_MATCH")\n        status = next(iter(statuses))\n        if status not in {"APPLIED", "INTRODUCED"}:\n            raise AggregationManualReview("KITU_CHILD_STATUS_NOT_SUPPORTED")\n        if any(x.status_ex_raw not in (None, "", "WAIT_TRANSFER_TO_OWNER") for x in children):\n            raise AggregationManualReview("KITU_CHILD_STATUS_EX_NOT_SUPPORTED")\n\n    for child in children:\n        if child.owner_inn != owner:\n            raise AggregationManualReview("LEGACY_NON_OWNER_FLOW_NOT_ENABLED")\n        if child.parent:\n            raise AggregationManualReview("CHILD_ALREADY_AGGREGATED")\n        if child.package_type is None:\n            raise AggregationManualReview("UNKNOWN_RAW_PACKAGE_TYPE")\n        if mixed_pg and not child.product_group:\n            raise AggregationManualReview("KITU_CHILD_PRODUCT_GROUP_REQUIRED")\n        validate_lp_relation(PackageType.BOX, child.package_type, child_pg=child.product_group or M6_PG, mixed_pg=mixed_pg)\n\n    if not mixed_pg and status == "APPLIED" and len({x.emission_type for x in children}) != 1:\n        raise AggregationManualReview("KITU_APPLIED_EMISSION_MISMATCH")\n    if mixed_pg and not any(x.product_group == leading_pg for x in children):\n        raise AggregationManualReview("KITU_LEADING_PG_CHILD_REQUIRED")\n'''
Path(p).write_text(s[:start] + box_func + s[end:], encoding="utf-8")

s = Path(p).read_text(encoding="utf-8")
start = s.index("def validate_reaggregation_preconditions(")
end = s.index("\n\ndef validate_disaggregation_preconditions(", start)
reagg_func = '''def validate_reaggregation_preconditions(\n    *,\n    parent: CisAggregationSnapshot,\n    children: Sequence[CisAggregationSnapshot],\n    reaggregation_type: str,\n    participant_inn: str,\n    nested_box_codes: frozenset[str] = frozenset(),\n    remaining_children: Sequence[CisAggregationSnapshot] = (),\n    leading_pg: str = M6_PG,\n    mixed_pg: bool = False,\n    runtime_formed_status_values: frozenset[str] = frozenset(),\n) -> None:\n    owner = _inn(participant_inn, "participant_inn")\n    if parent.package_type not in {PackageType.BOX, PackageType.SET}:\n        raise AggregationManualReview("REAGGREGATION_PARENT_NOT_SUPPORTED_FOR_LP")\n    if parent.owner_inn != owner:\n        raise AggregationManualReview("LEGACY_NON_OWNER_FLOW_NOT_ENABLED")\n    if reaggregation_type not in {"ADDING", "REMOVING"}:\n        raise AggregationContractError("reaggregation_type must be ADDING or REMOVING")\n    if not children:\n        raise AggregationContractError("reaggregation children required")\n\n    if mixed_pg:\n        if parent.package_type is not PackageType.BOX:\n            raise AggregationManualReview("MULTIPRODUCT_REAGGREGATION_REQUIRES_BOX_PARENT")\n        if parent.status_raw not in runtime_formed_status_values:\n            raise AggregationManualReview("MULTIPRODUCT_KITU_PARENT_STATUS_RUNTIME_CONFIRMATION_REQUIRED")\n        if parent.status_ex_raw not in (None, ""):\n            raise AggregationManualReview("MULTIPRODUCT_KITU_PARENT_STATUS_EX_NOT_SUPPORTED")\n    else:\n        if parent.status_raw not in {"APPLIED", "INTRODUCED"}:\n            raise AggregationManualReview("REAGGREGATION_PARENT_STATUS_NOT_SUPPORTED")\n        if parent.status_ex_raw not in (None, ""):\n            raise AggregationManualReview("REAGGREGATION_PARENT_STATUS_EX_NOT_SUPPORTED")\n\n    seen: set[str] = set()\n    for child in children:\n        if child.cis in seen:\n            raise AggregationContractError("reaggregation children must be unique")\n        seen.add(child.cis)\n        if child.owner_inn != owner:\n            raise AggregationManualReview("LEGACY_NON_OWNER_FLOW_NOT_ENABLED")\n        if mixed_pg:\n            if child.status_raw != "INTRODUCED" and child.status_raw not in runtime_formed_status_values:\n                raise AggregationManualReview("MULTIPRODUCT_KITU_CHILD_STATUS_NOT_CONFIRMED")\n            if child.status_ex_raw not in (None, "", "WAIT_TRANSFER_TO_OWNER"):\n                raise AggregationManualReview("MULTIPRODUCT_KITU_CHILD_STATUS_EX_NOT_SUPPORTED")\n            if not child.product_group:\n                raise AggregationManualReview("KITU_CHILD_PRODUCT_GROUP_REQUIRED")\n        else:\n            if child.status_raw != parent.status_raw:\n                raise AggregationManualReview("REAGGREGATION_STATUS_MISMATCH")\n            allowed_status_ex = {None, ""}\n            if child.cis in nested_box_codes:\n                allowed_status_ex.add("WAIT_TRANSFER_TO_OWNER")\n            if child.status_ex_raw not in allowed_status_ex:\n                raise AggregationManualReview("REAGGREGATION_STATUS_EX_NOT_SUPPORTED")\n            if parent.status_raw == "APPLIED" and child.emission_type in {"REMARK", "REAPPLY"}:\n                raise AggregationManualReview("REAGGREGATION_APPLIED_REMARK_REAPPLY_FORBIDDEN")\n        if child.cis in nested_box_codes:\n            if child.package_type is not PackageType.BOX or parent.package_type is not PackageType.BOX:\n                raise AggregationContractError("kitu item is only valid for BOX inside BOX")\n        if child.package_type is None:\n            raise AggregationManualReview("UNKNOWN_RAW_PACKAGE_TYPE")\n        validate_lp_relation(parent.package_type, child.package_type, child_pg=child.product_group or M6_PG, mixed_pg=mixed_pg)\n        if reaggregation_type == "ADDING" and child.parent not in (None, ""):\n            raise AggregationManualReview("ADDING_CHILD_ALREADY_AGGREGATED")\n        if reaggregation_type == "REMOVING" and child.parent != parent.cis:\n            raise AggregationManualReview("REMOVING_CHILD_NOT_IN_PARENT")\n\n    if parent.package_type is PackageType.SET and any(x.package_type not in {PackageType.UNIT, PackageType.BUNDLE} for x in children):\n        raise AggregationContractError("SET transformation permits only UNIT/BUNDLE")\n    if parent.package_type is PackageType.BOX and mixed_pg and remaining_children:\n        for child in remaining_children:\n            if child.owner_inn != owner:\n                raise AggregationManualReview("LEGACY_NON_OWNER_FLOW_NOT_ENABLED")\n            if child.status_raw != "INTRODUCED" and child.status_raw not in runtime_formed_status_values:\n                raise AggregationManualReview("MULTIPRODUCT_KITU_REMAINING_CHILD_STATUS_NOT_CONFIRMED")\n            if child.status_ex_raw not in (None, "", "WAIT_TRANSFER_TO_OWNER"):\n                raise AggregationManualReview("MULTIPRODUCT_KITU_REMAINING_STATUS_EX_NOT_SUPPORTED")\n            if not child.product_group:\n                raise AggregationManualReview("KITU_CHILD_PRODUCT_GROUP_REQUIRED")\n        if not any(x.product_group == leading_pg for x in remaining_children):\n            raise AggregationManualReview("KITU_LEADING_PG_CHILD_REQUIRED_AFTER_REMOVAL")\n'''
Path(p).write_text(s[:start] + reagg_func + s[end:], encoding="utf-8")

p = "tests/test_m6_aggregation.py"
replace_once(p, '''    prepare_aggregation_document, validate_atk_preconditions, validate_box_preconditions,\n    validate_lp_relation, validate_set_preconditions,\n''', '''    prepare_aggregation_document, validate_atk_preconditions, validate_box_preconditions,\n    validate_aggregate_identifier, validate_lp_relation, validate_set_preconditions,\n''')
replace_once(p, '''    mixed = (snap(C1, pg="lp"), snap(C2, PackageType.GROUP, pg="milk"))\n    validate_box_preconditions(parent=None, children=mixed, participant_inn=INN, mixed_pg=True, leading_pg="lp")\n''', '''    mixed = (\n        snap(C1, pg="lp", status="INTRODUCED", status_ex=None),\n        snap(C2, PackageType.GROUP, pg="milk", status="INTRODUCED", status_ex="WAIT_TRANSFER_TO_OWNER"),\n    )\n    validate_box_preconditions(parent=None, children=mixed, participant_inn=INN, mixed_pg=True, leading_pg="lp")\n''')
replace_once(p, '''    with pytest.raises(AggregationManualReview, match="LEADING_PG"):\n        validate_box_preconditions(parent=None, children=(snap(C2, PackageType.GROUP, pg="milk"),), participant_inn=INN, mixed_pg=True, leading_pg="lp")\n''', '''    with pytest.raises(AggregationManualReview, match="LEADING_PG"):\n        validate_box_preconditions(parent=None, children=(snap(C2, PackageType.GROUP, pg="milk", status="INTRODUCED"),), participant_inn=INN, mixed_pg=True, leading_pg="lp")\n''')
replace_once(p, '''    box_parent=snap(PARENT, PackageType.BOX, status="INTRODUCED")\n    removed=snap(C1, PackageType.UNIT, status="INTRODUCED", parent=PARENT)\n    with pytest.raises(AggregationManualReview, match="LEADING_PG"):\n        validate_reaggregation_preconditions(parent=box_parent, children=(removed,), reaggregation_type="REMOVING", participant_inn=INN, remaining_children=(snap(C2, PackageType.GROUP, pg="milk", status="INTRODUCED", parent=PARENT),), mixed_pg=True, leading_pg="lp")\n''', '''    box_parent=snap(PARENT, PackageType.BOX, status="RUNTIME_FORMED_VALUE")\n    removed=snap(C1, PackageType.UNIT, status="INTRODUCED", parent=PARENT)\n    with pytest.raises(AggregationManualReview, match="LEADING_PG"):\n        validate_reaggregation_preconditions(\n            parent=box_parent, children=(removed,), reaggregation_type="REMOVING", participant_inn=INN,\n            remaining_children=(snap(C2, PackageType.GROUP, pg="milk", status="INTRODUCED", parent=PARENT),),\n            mixed_pg=True, leading_pg="lp", runtime_formed_status_values=frozenset({"RUNTIME_FORMED_VALUE"}),\n        )\n''')

s = Path(p).read_text(encoding="utf-8")
insertion_point = s.index("\ndef test_disaggregation_preconditions_no_formed_enum_and_runtime_formed_value_is_explicit()")
new_tests = r'''

def test_aggregate_identifier_exact_charset_boundaries_and_generic_child_validator_separate() -> None:
    allowed_specials = "A%&'\"()*+,_./:;<?!"
    assert len(allowed_specials) == 18
    assert validate_aggregate_identifier(allowed_specials) == allowed_specials
    assert validate_aggregate_identifier("A" * 18) == "A" * 18
    assert validate_aggregate_identifier("Z" * 74) == "Z" * 74
    for invalid in ("A" * 17, "A" * 75, "A" * 17 + "@", "A" * 17 + "Ж", "A" * 17 + " "):
        with pytest.raises(AggregationContractError):
            validate_aggregate_identifier(invalid)
    child_with_at = "010123456789012321@CHILD"
    wire = AggregationUnit(PARENT, UnitSerialNumberType.BOX, (child_with_at,)).to_wire()
    assert wire["sntins"] == [child_with_at]


def test_aggregate_identifier_validator_is_used_on_parent_wire_positions() -> None:
    bad = "A" * 17 + "@"
    with pytest.raises(AggregationContractError):
        AggregationUnit(bad, UnitSerialNumberType.BOX, (C1,)).to_wire()
    with pytest.raises(AggregationContractError):
        SetAggregationUnit(bad, (C1,)).to_wire()
    with pytest.raises(AggregationContractError):
        ReaggregationDocument(INN, "ADDING", bad, (ReaggregationItem(uit_uitu=C1),)).to_wire()
    with pytest.raises(AggregationContractError):
        ReaggregationItem(kitu=bad).to_wire()
    with pytest.raises(AggregationContractError):
        DisaggregationDocument(INN, (bad,)).to_wire()


def test_multiproduct_kitu_formation_uses_current_status_semantics_and_runtime_gate() -> None:
    introduced = (
        snap(C1, pg="lp", status="INTRODUCED", status_ex=None),
        snap(C2, PackageType.GROUP, pg="milk", status="INTRODUCED", status_ex="WAIT_TRANSFER_TO_OWNER"),
    )
    validate_box_preconditions(parent=None, children=introduced, participant_inn=INN, mixed_pg=True, leading_pg="lp")
    with pytest.raises(AggregationManualReview, match="STATUS_NOT_CONFIRMED"):
        validate_box_preconditions(
            parent=None,
            children=(snap(C1, pg="lp", status="APPLIED"), snap(C2, PackageType.GROUP, pg="milk", status="INTRODUCED")),
            participant_inn=INN, mixed_pg=True, leading_pg="lp",
        )
    unknown_formed = (
        snap(C1, pg="lp", status="RUNTIME_FORMED_VALUE"),
        snap(C2, PackageType.GROUP, pg="milk", status="INTRODUCED", status_ex="WAIT_TRANSFER_TO_OWNER"),
    )
    with pytest.raises(AggregationManualReview, match="STATUS_NOT_CONFIRMED"):
        validate_box_preconditions(parent=None, children=unknown_formed, participant_inn=INN, mixed_pg=True, leading_pg="lp")
    validate_box_preconditions(
        parent=None, children=unknown_formed, participant_inn=INN, mixed_pg=True, leading_pg="lp",
        runtime_formed_status_values=frozenset({"RUNTIME_FORMED_VALUE"}),
    )
    import wbcz.aggregation as a
    assert not hasattr(a, "FORMED")


def test_multiproduct_kitu_transformation_removes_old_status_equality_and_runtime_gates_parent() -> None:
    parent = snap(PARENT, PackageType.BOX, pg="lp", status="RUNTIME_FORMED_VALUE", status_ex=None)
    introduced = snap(C1, PackageType.UNIT, pg="lp", status="INTRODUCED", status_ex=None, parent=PARENT)
    formed = snap(C2, PackageType.GROUP, pg="milk", status="RUNTIME_FORMED_VALUE", status_ex="WAIT_TRANSFER_TO_OWNER", parent=PARENT)
    remaining = (snap(C3, PackageType.UNIT, pg="lp", status="INTRODUCED", status_ex="WAIT_TRANSFER_TO_OWNER", parent=PARENT),)
    with pytest.raises(AggregationManualReview, match="PARENT_STATUS_RUNTIME_CONFIRMATION_REQUIRED"):
        validate_reaggregation_preconditions(
            parent=parent, children=(introduced,), reaggregation_type="REMOVING", participant_inn=INN,
            mixed_pg=True, leading_pg="lp", remaining_children=remaining,
        )
    runtime = frozenset({"RUNTIME_FORMED_VALUE"})
    validate_reaggregation_preconditions(
        parent=parent, children=(introduced,), reaggregation_type="REMOVING", participant_inn=INN,
        mixed_pg=True, leading_pg="lp", remaining_children=remaining, runtime_formed_status_values=runtime,
    )
    validate_reaggregation_preconditions(
        parent=parent, children=(formed,), reaggregation_type="REMOVING", participant_inn=INN,
        mixed_pg=True, leading_pg="lp", remaining_children=remaining, runtime_formed_status_values=runtime,
    )
    with pytest.raises(AggregationManualReview, match="STATUS_NOT_CONFIRMED"):
        validate_reaggregation_preconditions(
            parent=parent,
            children=(snap(C2, PackageType.GROUP, pg="milk", status="UNKNOWN_FORMED_RAW", parent=PARENT),),
            reaggregation_type="REMOVING", participant_inn=INN, mixed_pg=True, leading_pg="lp",
            remaining_children=remaining, runtime_formed_status_values=runtime,
        )


def test_ordinary_kitu_retains_identical_applied_or_introduced_rules() -> None:
    validate_box_preconditions(parent=None, children=(snap(C1), snap(C2)), participant_inn=INN)
    with pytest.raises(AggregationManualReview, match="STATUSES_MUST_MATCH"):
        validate_box_preconditions(
            parent=None, children=(snap(C1, status="APPLIED"), snap(C2, status="INTRODUCED")), participant_inn=INN
        )
'''
Path(p).write_text(s[:insertion_point] + new_tests + s[insertion_point:], encoding="utf-8")

p = "docs/M6_AGGREGATION_CONTRACT.md"
replace_once(
    p,
    '''For `lp`, `GROUP` is not exposed as a formable parent. `SET` accepts only direct `UNIT` or `BUNDLE`. `BOX` accepts `UNIT`, `BUNDLE`, `SET`, and nested `BOX`; `GROUP` can only appear as a legitimate non-lp child in a mixed-PG KITU. Nested `SET` is fail-closed. ATK is a separate customs aggregate domain.\n''',
    '''For `lp`, `GROUP` is not exposed as a formable parent. `SET` accepts only direct `UNIT` or `BUNDLE`. `BOX` accepts `UNIT`, `BUNDLE`, `SET`, and nested `BOX`; `GROUP` can only appear as a legitimate non-lp child in a mixed-PG KITU. Nested `SET` is fail-closed. ATK is a separate customs aggregate domain.\n\nKIGU/KITU/KIN aggregate identifiers use a dedicated official validator and are not conflated with generic child CIS/KI validation. The aggregate identifier is 18..74 characters and only permits `A-Z`, `a-z`, `0-9`, `%`, `&`, `'`, `\"`, `(`, `)`, `*`, `+`, `,`, `_`, `.`, `/`, `:`, `;`, `<`, `?`, `!`. Whitespace, Cyrillic, `@`, and every other character outside that set are rejected. This rule is applied to aggregate parent/set identifier wire positions; it is not blindly applied to child KI/KIK values whose representation contract differs.\n''',
)
replace_once(
    p,
    '''Mixed-PG KITU is supported as the current v726 contract, not downgraded to an old single-PG model. The leading PG is explicit in precondition evidence; at least one child must match it. Child compatibility is evaluated using each child's real PG/package type. Nested BOX is supported. The implementation does not invent a nesting-depth contract. Official non-owner/legacy traceability exceptions are not silently enabled.\n''',
    '''Mixed-PG KITU uses the current v664 rules included in v726, not the ordinary single-PG status logic. Ordinary KITU retains its source-confirmed identical-child-status rule with `APPLIED`/`INTRODUCED`; `APPLIED` children also require matching emission semantics. Multiproduct KITU instead accepts each child only when raw status is `INTRODUCED` or belongs to an explicitly supplied runtime-confirmed set corresponding to textual «Сформирован». `APPLIED` is not accepted merely because ordinary KITU allows it. Different child raw statuses are allowed across INTRODUCED/runtime-confirmed-formed branches, and `statusEx` may independently be absent or `WAIT_TRANSFER_TO_OWNER`.\n\nThe exact raw enum behind textual «Сформирован» is still unresolved, so no `FORMED` enum is invented. `runtime_formed_status_values` defaults empty and the formed-state path therefore fails closed until explicitly confirmed. Capability honesty: `MULTIPRODUCT_KITU_INTRODUCED_PATH=IMPLEMENTED`; `MULTIPRODUCT_KITU_FORMED_PATH=RUNTIME_GATED`. Multiproduct transformation removes the old child-status-equals-parent assumption. Because the authoritative source does not establish an exact raw parent status for that branch, mixed-PG transformation also requires an explicitly runtime-confirmed parent formed-state raw value instead of inventing one. Leading-PG requirements, removal validity, owner policy, nested BOX rules, and actual child PG compatibility remain enforced.\n''',
)

p = ".github/workflows/m6-aggregation-validation.yml"
replace_once(
    p,
    '''              M5_AGGREGATION_HARDENING, reconcile_m5_aggregation_side_effect,\n          )\n''',
    '''              M5_AGGREGATION_HARDENING, reconcile_m5_aggregation_side_effect,\n              AGGREGATE_IDENTIFIER_ALLOWED_CHARS, validate_aggregate_identifier,\n          )\n''',
)
replace_once(
    p,
    '''          assert M5_AGGREGATION_HARDENING['LK_RECEIPT_CANCEL'].startswith('REREAD_RELATION')\n          assert callable(reconcile_m5_aggregation_side_effect)\n''',
    '''          assert M5_AGGREGATION_HARDENING['LK_RECEIPT_CANCEL'].startswith('REREAD_RELATION')\n          assert callable(reconcile_m5_aggregation_side_effect)\n          assert '@' not in AGGREGATE_IDENTIFIER_ALLOWED_CHARS\n          assert 'Ж' not in AGGREGATE_IDENTIFIER_ALLOWED_CHARS\n          assert validate_aggregate_identifier('A' * 18) == 'A' * 18\n''',
)

for file in ("src/wbcz/aggregation.py", "tests/test_m6_aggregation.py"):
    compile(Path(file).read_text(encoding="utf-8"), file, "exec")
