from __future__ import annotations

import argparse
import getpass
import sys

from sqlalchemy.exc import IntegrityError

from .auth import hash_password
from .config import WebConfig
from .db import build_session_factory
from .models import User
from .repositories import AuditRepository, SessionRepository, UserRepository
from .services.authorization import AuthorizationError, BootstrapService
from .services.audit_history import (
    ActorContext,
    ActorKind,
    AuditOutcome,
    AuditService,
    AuditTenantScope,
    AuthorizationDecision,
    SubjectRef,
    SubjectType,
    TraceContext,
)


def _configure_audit_context(db, config: WebConfig) -> None:
    if config.audit_pseudonym_key:
        db.info["audit_pseudonym_key"] = config.audit_pseudonym_key.encode("utf-8")
        db.info["audit_pseudonym_key_id"] = config.audit_pseudonym_key_id


def _create_user(args, db) -> int:
    username = args.username.strip()
    if not username:
        print("Username is required", file=sys.stderr)
        return 2
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match", file=sys.stderr)
        return 2
    try:
        user = User(
            username=username,
            password_hash=hash_password(password),
            is_active=True,
            is_admin=bool(args.admin),
        )
        db.add(user)
        db.flush()
        AuditRepository(db).append(
            "USER_CREATED",
            user_id=user.id,
            entity_type="user",
            entity_id=str(user.id),
            metadata={"username": username, "is_admin": user.is_admin},
        )
        db.commit()
    except (ValueError, IntegrityError) as exc:
        db.rollback()
        print(f"Cannot create user: {exc}", file=sys.stderr)
        return 2
    print(f"Created user {username} (id={user.id}, admin={user.is_admin})")
    return 0


def _disable_user(args, db) -> int:
    user = UserRepository(db).by_username(args.username.strip())
    if user is None:
        print("User not found", file=sys.stderr)
        return 2
    if not user.is_active:
        print("User is already disabled")
        return 0
    user.is_active = False
    revoked = SessionRepository(db).revoke_all_for_user(user.id)
    AuditRepository(db).append(
        "USER_DISABLED",
        user_id=user.id,
        entity_type="user",
        entity_id=str(user.id),
        metadata={"sessions_revoked": revoked},
    )
    AuditRepository(db).append(
        "SESSION_REVOKED",
        user_id=user.id,
        entity_type="user",
        entity_id=str(user.id),
        metadata={"count": revoked, "reason": "user_disabled"},
    )
    db.commit()
    print(f"Disabled user {user.username}")
    return 0


def _list_users(args, db) -> int:
    for user in UserRepository(db).list_all():
        print(
            f"{user.id}\t{user.username}\tactive={user.is_active}\tadmin={user.is_admin}"
            f"\tcreated={user.created_at.isoformat() if user.created_at else ''}"
        )
    return 0


def _bootstrap_owner(args, db) -> int:
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match", file=sys.stderr)
        return 2
    try:
        user, org, participant, _ = BootstrapService(db).bootstrap(
            username=args.username,
            password=password,
            organisation_name=args.organisation,
            participant_inn=args.inn,
            participant_name=args.participant_name,
        )
        db.commit()
    except (ValueError, AuthorizationError, IntegrityError) as exc:
        db.rollback()
        print(f"Cannot bootstrap owner: {exc}", file=sys.stderr)
        return 2
    print(
        f"Bootstrapped OWNER {user.username} organisation={org.id} participant={participant.id}"
    )
    return 0


def _verify_audit_chain(args, db) -> int:
    if bool(args.system) == bool(args.organisation_id):
        print("Select exactly one of --system or --organisation-id", file=sys.stderr)
        return 2
    service = AuditService(
        db,
        pseudonym_key=db.info.get("audit_pseudonym_key"),
        pseudonym_key_id=db.info.get("audit_pseudonym_key_id"),
    )
    result = service.verify_chain(
        organisation_id=args.organisation_id,
        system=bool(args.system),
        from_sequence=args.from_sequence,
        expected_previous_hash=args.expected_previous_hash,
    )
    scope = "SYSTEM" if args.system else f"ORGANISATION:{args.organisation_id}"
    print(f"scope={scope}")
    print(f"chain_id={result.chain_id}")
    print(f"checked_range={result.checked_from}..{result.checked_to}")
    print(f"checked_count={result.checked_count}")
    print(f"stored_head_sequence={result.stored_head_sequence}")
    print(f"stored_head_hash={result.stored_head_hash}")
    print(f"checkpoint_status={result.checkpoint_status}")
    print(f"status={result.status}")
    if result.first_invalid_sequence is not None:
        print(f"first_invalid_sequence={result.first_invalid_sequence}")
    if result.reason:
        print(f"reason={result.reason}")

    if result.status != "VALID":
        # Do not write integrity evidence into the chain already known/suspected to be invalid.
        # For organisation-chain failures, record only a bounded SYSTEM-chain meta fact.
        if not args.system:
            try:
                system = service.system_chain()
                service.append(
                    event_type="CHAIN_VERIFICATION_FAILED",
                    actor=ActorContext(ActorKind.CLI_ADMIN),
                    tenant=AuditTenantScope.system(),
                    subject=SubjectRef(SubjectType.AUDIT_CHAIN, system.chain_id),
                    secondary_subject=SubjectRef(
                        SubjectType.ORGANISATION,
                        str(args.organisation_id),
                    ),
                    outcome=AuditOutcome.FAILED,
                    authorization_decision=AuthorizationDecision.NOT_APPLICABLE,
                    trace=TraceContext(
                        event_key=(
                            f"verification-failed:{args.organisation_id}:"
                            f"{result.first_invalid_sequence}:{result.reason}"
                        )[:256]
                    ),
                    metadata={
                        "first_invalid_sequence": result.first_invalid_sequence,
                        "failure_reason": (result.reason or "unknown")[:512],
                        "verification_status": "INVALID",
                    },
                )
                db.commit()
            except Exception:
                db.rollback()
        return 1
    db.rollback()
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="WBCZ web admin CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create-user")
    create.add_argument("username")
    create.add_argument(
        "--admin",
        action="store_true",
        help="legacy compatibility only; does not grant M12 permissions",
    )
    disable = sub.add_parser("disable-user")
    disable.add_argument("username")
    sub.add_parser("list-users")

    bootstrap = sub.add_parser("bootstrap-owner")
    bootstrap.add_argument("username")
    bootstrap.add_argument("--organisation", required=True)
    bootstrap.add_argument("--inn", required=True)
    bootstrap.add_argument("--participant-name", default=None)

    verify = sub.add_parser("verify-audit-chain")
    selection = verify.add_mutually_exclusive_group(required=True)
    selection.add_argument("--organisation-id", default=None)
    selection.add_argument("--system", action="store_true")
    verify.add_argument("--from-sequence", type=int, default=1)
    verify.add_argument("--expected-previous-hash", default=None)

    args = parser.parse_args()
    config = WebConfig.from_env()
    db = build_session_factory(config)()
    _configure_audit_context(db, config)
    try:
        if args.command == "bootstrap-owner":
            code = _bootstrap_owner(args, db)
        elif args.command == "create-user":
            code = _create_user(args, db)
        elif args.command == "disable-user":
            code = _disable_user(args, db)
        elif args.command == "verify-audit-chain":
            code = _verify_audit_chain(args, db)
        else:
            code = _list_users(args, db)
    finally:
        db.close()
    raise SystemExit(code)


if __name__ == "__main__":
    main()
