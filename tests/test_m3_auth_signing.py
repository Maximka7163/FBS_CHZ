from __future__ import annotations

import base64
from dataclasses import fields
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from wbcz.windows_agent import (
    AgentJob,
    AgentJobType,
    AgentSecurityError,
    AgentSessionManager,
    WindowsCryptoProDocumentSigner,
)
from wbcz_ui.live_true_api import (
    AuthSession,
    JsonlLiveAudit,
    ReadOnlyTrueApiTransport,
    TrueApiAuthenticator,
    TrueApiHttpError,
    TrueApiProtocolError,
    WindowsCryptoProAuthSigner,
)

OWN = "1234567890"


class FakeHeaders(dict):
    pass


class FakeHttpResponse:
    def __init__(self, status, body, headers=None):
        self.status = status
        self._body = body
        self.headers = FakeHeaders(headers or {})

    def read(self):
        return self._body


class FakeConnection:
    def __init__(self, response, calls, host, port, timeout=None):
        self.response = response
        self.calls = calls
        self.host = host
        self.port = port
        self.timeout = timeout
        self.headers = {}
        self.data = None

    def putrequest(self, method, target, skip_host=False):
        self.method = method
        self.target = target

    def putheader(self, name, value):
        self.headers[name] = value

    def endheaders(self, data=None):
        self.data = data
        self.calls.append(self)

    def getresponse(self):
        return self.response

    def close(self):
        pass


class FakeTunnel:
    local_port = 41414

    def session_marker(self):
        return 0

    def assert_gost_session(self, marker=0):
        return None

    def diagnostics(self):
        return {"mechanism": "test"}


def transport_for(tmp_path, responses):
    calls = []
    queue = list(responses)

    def factory(host, port, timeout=None):
        return FakeConnection(queue.pop(0), calls, host, port, timeout)

    return ReadOnlyTrueApiTransport(
        audit=JsonlLiveAudit(tmp_path / "auth.jsonl"),
        tunnel=FakeTunnel(),
        connection_factory=factory,
    ), calls


def test_auth_key_get_has_no_auth_header_and_uuidtoken_is_primary(tmp_path):
    key = FakeHttpResponse(200, json.dumps({"uuid": "u-1", "data": "  exact\nchallenge  "}).encode(), {})
    signin = FakeHttpResponse(
        200,
        json.dumps({
            "token": "legacy-not-used",
            "uuidToken": "uuid-token-used",
            "expireDate": "2026-09-17T10:00:00+05:00",
        }).encode(),
        {},
    )
    transport, calls = transport_for(tmp_path, [key, signin])

    class Signer:
        def __init__(self):
            self.values = []
        def sign_auth_challenge(self, value):
            self.values.append(value)
            return "ATTACHED"

    signer = Signer()
    session = TrueApiAuthenticator(transport, signer, OWN).authenticate()
    assert signer.values == ["  exact\nchallenge  "]
    assert session.uuid_token == "uuid-token-used"
    assert session.bearer_token == "uuid-token-used"
    assert session.expire_date == datetime(2026, 9, 17, 5, 0, tzinfo=timezone.utc)
    assert calls[0].method == "GET"
    assert calls[0].target == "/api/v3/true-api/auth/key"
    assert "Authorization" not in calls[0].headers
    assert calls[1].method == "POST"
    assert calls[1].target == "/api/v3/true-api/auth/simpleSignIn"
    assert json.loads(calls[1].data) == {
        "uuid": "u-1",
        "data": "ATTACHED",
        "inn": OWN,
        "unitedToken": True,
    }
    assert "Authorization" not in calls[1].headers


def test_auth_requires_uuid_data_uuidtoken_and_timezone_expiry():
    class Transport:
        def __init__(self, key, signin):
            self.key = key
            self.signin = signin
        def request_json(self, method, path, **kwargs):
            return self.key if path.endswith("/key") else self.signin

    class Signer:
        def sign_auth_challenge(self, value):
            return "sig"

    with pytest.raises(TrueApiProtocolError):
        TrueApiAuthenticator(Transport({"data": "x"}, {}), Signer(), OWN).authenticate()
    with pytest.raises(TrueApiProtocolError):
        TrueApiAuthenticator(
            Transport({"uuid": "u", "data": "x"}, {"token": "legacy", "expireDate": "2026-09-17T10:00:00Z"}),
            Signer(),
            OWN,
        ).authenticate()
    with pytest.raises(TrueApiProtocolError, match="timezone"):
        TrueApiAuthenticator(
            Transport({"uuid": "u", "data": "x"}, {"uuidToken": "u", "expireDate": "2026-09-17T10:00:00"}),
            Signer(),
            OWN,
        ).authenticate()


def test_session_expiry_and_401_clear_local_session_then_full_reauth():
    now = datetime(2026, 9, 17, 5, 0, tzinfo=timezone.utc)

    class Auth:
        def __init__(self):
            self.calls = 0
        def authenticate(self):
            self.calls += 1
            return AuthSession(f"uuid-{self.calls}", now + timedelta(minutes=3 * self.calls))

    clock = [now]
    auth = Auth()
    manager = AgentSessionManager(auth, now=lambda: clock[0])
    assert manager.bearer_token() == "uuid-1"
    clock[0] = now + timedelta(minutes=2)
    assert manager.bearer_token() == "uuid-2"
    manager.observe_http_status(401)
    assert manager.expire_date is None
    assert manager.bearer_token() == "uuid-3"
    assert auth.calls == 3


def test_failed_reauth_does_not_leave_expired_token():
    now = datetime(2026, 9, 17, 5, 0, tzinfo=timezone.utc)

    class Auth:
        def __init__(self):
            self.calls = 0
        def authenticate(self):
            self.calls += 1
            if self.calls == 1:
                return AuthSession("old", now + timedelta(minutes=1))
            raise RuntimeError("auth failed")

    manager = AgentSessionManager(Auth(), now=lambda: now, refresh_margin=timedelta(0))
    assert manager.bearer_token() == "old"
    manager._now = lambda: now + timedelta(minutes=2)
    with pytest.raises(RuntimeError):
        manager.bearer_token()
    assert manager.expire_date is None


def test_auth_signer_attached_and_exact_utf8_bytes(tmp_path):
    cryptcp = tmp_path / "cryptcp.exe"
    cryptcp.write_bytes(b"x")
    seen = {}

    class Inspector:
        def inspect(self):
            return {}

    def runner(command, **kwargs):
        source = Path(command[command.index("-fext") - 1])
        seen["bytes"] = source.read_bytes()
        seen["command"] = command
        source.with_name(source.name + ".sgn").write_bytes(b"AUTH")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    signer = WindowsCryptoProAuthSigner("AA11", cryptcp_path=cryptcp, inspector=Inspector(), runner=runner)
    challenge = "  строка\nwith-space  "
    assert base64.b64decode(signer.sign_auth_challenge(challenge)) == b"AUTH"
    assert seen["bytes"] == challenge.encode("utf-8")
    assert "-attached" in seen["command"]
    assert "-pin" not in seen["command"]


def test_document_signer_detached_and_exact_json_bytes(tmp_path):
    cryptcp = tmp_path / "cryptcp.exe"
    cryptcp.write_bytes(b"x")
    seen = {}

    class Inspector:
        def inspect(self):
            return {}

    def runner(command, **kwargs):
        source = Path(command[command.index("-fext") - 1])
        seen["bytes"] = source.read_bytes()
        seen["command"] = command
        source.with_name(source.name + ".sgn").write_bytes(b"DOC")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    signer = WindowsCryptoProDocumentSigner(
        certificate_thumbprint="AA11",
        participant_inn=OWN,
        cryptcp_path=cryptcp,
        inspector=Inspector(),
        runner=runner,
    )
    payload = b'{"inn":"1234567890","x":1}'
    signature, _ = signer.sign_document_bytes(
        operation_id="op",
        document_type="LK_RECEIPT",
        pg="lp",
        expected_inn=OWN,
        document_sha256=hashlib.sha256(payload).hexdigest(),
        payload=payload,
    )
    assert base64.b64decode(signature) == b"DOC"
    assert seen["bytes"] == payload
    assert "-attached" not in seen["command"]
    assert "-der" in seen["command"] and "-strict" in seen["command"]

    with pytest.raises(AgentSecurityError):
        signer.sign_document_bytes(
            operation_id="op",
            document_type="LK_RECEIPT",
            pg="lp",
            expected_inn=OWN,
            document_sha256="0" * 64,
            payload=payload,
        )

    bad = b"[1,2,3]"
    with pytest.raises(AgentSecurityError, match="root"):
        signer.sign_document_bytes(
            operation_id="op",
            document_type="LK_RECEIPT",
            pg="lp",
            expected_inn=OWN,
            document_sha256=hashlib.sha256(bad).hexdigest(),
            payload=bad,
        )


def test_agent_protocol_cannot_request_arbitrary_auth_signing_or_thumbprint():
    names = {f.name for f in fields(AgentJob)}
    forbidden = {
        "auth_challenge",
        "challenge",
        "bytes_to_sign",
        "sign_payload",
        "certificate_thumbprint",
        "pin",
        "private_key",
        "uuid_token",
        "bearer_token",
    }
    assert names.isdisjoint(forbidden)
    assert all("AUTH_SIGN" not in item.value and "SIGN_AUTH" not in item.value for item in AgentJobType)


def test_auth_error_json_xml_text_empty_are_safe_and_redacted(tmp_path):
    bodies = [
        (b'{"message":"Bearer SUPERSECRET"}', "application/json"),
        (b'<error><token>SUPERSECRET</token></error>', "application/xml"),
        (b'pin=SUPERSECRET', "text/plain"),
        (b'', "text/plain"),
    ]
    for body, content_type in bodies:
        transport, _ = transport_for(tmp_path, [FakeHttpResponse(401, body, {"Content-Type": content_type})])
        with pytest.raises(TrueApiHttpError) as exc:
            transport.request_json("GET", "/auth/key")
        error = exc.value
        assert error.status == 401
        assert error.body_sha256 == hashlib.sha256(body).hexdigest()
        assert "SUPERSECRET" not in str(error)
        assert "SUPERSECRET" not in (tmp_path / "auth.jsonl").read_text(encoding="utf-8")
