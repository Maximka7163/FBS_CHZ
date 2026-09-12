from __future__ import annotations

import ast
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess

import pytest

from wbcz.event_store import EventStore
from wbcz.models import KiState
from wbcz.true_api import TrueApiError
from wbcz_ui.application import UiApplication
from wbcz_ui.live_true_api import (
    AuthSession,
    CryptoProGostTlsTunnel,
    GostTlsUnavailable,
    LiveReadOnlyConfig,
    LiveTrueApiClient,
    ProductionMutationDisabled,
    PRODUCTION_BASE_URL,
    ReadOnlyTrueApiTransport,
    TrueApiAuthenticator,
    WindowsCryptoProAuthSigner,
    WindowsCryptoProCertificateInspector,
)

OWN = "1234567890"
ROOT = Path(__file__).parents[1]


def test_production_transport_has_no_urllib_or_httpsconnection_path():
    paths = [
        ROOT / "src" / "wbcz_ui" / "live_true_api.py",
        ROOT / "src" / "wbcz_ui" / "_live_true_api_base.py",
    ]
    trees = [ast.parse(path.read_text(encoding="utf-8")) for path in paths]
    imported = []
    names = []
    for node in (node for tree in trees for node in ast.walk(tree)):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
            names.extend(alias.name for alias in node.names)
    assert not any(name.startswith("urllib") for name in imported)
    assert "urlopen" not in names
    source = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    assert "HTTPSConnection" not in source
    assert "HTTPConnection" in source


def test_gost_tunnel_config_is_msspi_validating_and_production_only(tmp_path):
    exe = tmp_path / "stunnel_msspi.exe"
    exe.write_bytes(b"placeholder")
    tunnel = CryptoProGostTlsTunnel(exe)
    config = tunnel._config(45678, tmp_path / "stunnel.log")
    assert "client = yes" in config
    assert "msspi = yes" in config
    assert "sslVersion = TLSv1.2" in config
    assert (
        "ciphers = GOST2012-GOST8912-GOST8912:GOST2001-GOST89-GOST89"
        in config
    )
    assert "verify = 2" in config
    assert "checkHost = markirovka.crpt.ru" in config
    assert "sni = markirovka.crpt.ru" in config
    assert "connect = markirovka.crpt.ru:443" in config
    assert "verify = 0" not in config
    assert "msspi = 0" not in config
    upper = config.upper()
    for forbidden_cipher in ("AES", "CHACHA", "ECDHE", "RSA-AES"):
        assert forbidden_cipher not in upper
    assert tunnel.executable.name == "stunnel_msspi.exe"


def test_gost_word_in_configuration_is_not_session_proof(tmp_path):
    exe = tmp_path / "stunnel_msspi.exe"
    exe.write_bytes(b"x")
    tunnel = CryptoProGostTlsTunnel(exe)
    tunnel._log_path = tmp_path / "stunnel.log"
    tunnel._log_path.write_text(
        "Configuration loaded: ciphers = GOST2012-GOST8912-GOST8912\n"
        "TLSv1.2 connection attempt started\n",
        encoding="utf-8",
    )
    assert tunnel._gost_session_seen(0) is False
    with pytest.raises(GostTlsUnavailable):
        tunnel.assert_gost_session(0)


def test_gost_session_must_be_proven_from_cryptopro_diagnostics(tmp_path):
    exe = tmp_path / "stunnel_msspi.exe"
    exe.write_bytes(b"x")
    tunnel = CryptoProGostTlsTunnel(exe)
    tunnel._log_path = tmp_path / "stunnel.log"
    tunnel._log_path.write_text(
        "SECPKG_ATTR_CIPHER_INFO: CipherSuite: c100, "
        "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC\n",
        encoding="utf-8",
    )
    tunnel.assert_gost_session(0)
    tunnel._log_path.write_text(
        "TLSv1.2 connected (C02F)\n", encoding="utf-8"
    )
    with pytest.raises(GostTlsUnavailable):
        tunnel.assert_gost_session(0)


class PreflightTransport:
    def __init__(self):
        self.calls = []

    def request_json(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        if (method, path) == ("GET", "/auth/key"):
            return {"uuid": "u", "data": "challenge"}
        if (method, path) == ("POST", "/auth/simpleSignIn"):
            return {
                "uuidToken": "token",
                "expireDate": "2099-01-01T00:00:00Z",
            }
        raise AssertionError(path)

    def tls_diagnostics(self):
        return {
            "mechanism": "CryptoPro CSP stunnel-msspi / MSSPI GOST TLS",
            "gost_session_verified": True,
        }


class CountingSigner:
    def __init__(self):
        self.calls = []

    def sign_auth_challenge(self, challenge):
        self.calls.append(challenge)
        return "cms"


class CountingInspector:
    def __init__(self):
        self.calls = 0

    def inspect(self):
        self.calls += 1
        return {
            "certificate_found": True,
            "has_private_key": True,
            "not_expired": True,
            "gost_compatible": True,
            "cryptopro_provider": True,
        }


def test_tls_preflight_calls_only_auth_key_and_never_signs():
    transport = PreflightTransport()
    signer = CountingSigner()
    inspector = CountingInspector()
    authenticator = TrueApiAuthenticator(transport, signer, OWN)
    client = LiveTrueApiClient(
        transport,
        authenticator,
        certificate_inspector=inspector,
    )
    result = client.preflight()
    assert [(m, p) for m, p, _ in transport.calls] == [
        ("GET", "/auth/key")
    ]
    assert signer.calls == []
    assert inspector.calls == 1
    assert result["challenge_received"] is True
    assert result["certificate"]["cryptopro_provider"] is True


def test_successful_auth_does_not_call_cises_info():
    transport = PreflightTransport()
    signer = CountingSigner()
    client = LiveTrueApiClient(
        transport,
        TrueApiAuthenticator(transport, signer, OWN),
        certificate_inspector=CountingInspector(),
    )
    client.preflight()
    transport.calls.clear()
    result = client.authenticate()
    assert result["authenticated"] is True
    assert [(m, p) for m, p, _ in transport.calls] == [
        ("GET", "/auth/key"),
        ("POST", "/auth/simpleSignIn"),
    ]
    assert not any(path == "/cises/info" for _, path, _ in transport.calls)


class ApplicationAuthClient:
    def __init__(self):
        self.preflight_ok = False
        self.authenticated = False
        self.expire_date = None
        self.prime_calls = []

    def preflight(self):
        self.preflight_ok = True
        return {
            "crypto_pro_tls": True,
            "true_api_available": True,
            "challenge_received": True,
            "tls": {"gost_session_verified": True},
            "certificate": {"cryptopro_provider": True},
        }

    def authenticate(self):
        self.authenticated = True
        self.expire_date = datetime.now(timezone.utc) + timedelta(hours=1)
        return {
            "authenticated": True,
            "expire_date": self.expire_date.isoformat(),
            "submission": False,
            "document_signing": False,
        }

    def prime(self, kizes):
        self.prime_calls.append(list(kizes))

    def get_ki_state(self, kiz):
        return KiState(
            "IN_CIRCULATION",
            ownerInn=OWN,
            productGroup="lp",
        )


def live_config(tmp_path):
    return LiveReadOnlyConfig(
        True,
        OWN,
        "THUMB",
        PRODUCTION_BASE_URL,
        tmp_path / "live.jsonl",
    )


def test_successful_auth_alone_does_not_check_kiz_or_create_preview(
    tmp_path, wb_row, make_xlsx
):
    client = ApplicationAuthClient()
    app = UiApplication(
        tmp_path / "state.sqlite",
        live_config(tmp_path),
        lambda _: client,
    )
    source = make_xlsx([wb_row], "one.xlsx")
    app.import_bytes(source.name, source.read_bytes())
    app.live_preflight()
    auth = app.live_authenticate()
    assert auth["authenticated"] is True
    assert client.prime_calls == []
    with EventStore(app.db_path) as store:
        assert store.previews() == []
        assert store.count("documents") == 0


def test_one_kiz_cises_info_is_read_only_and_returns_diagnostics(
    tmp_path, wb_row, make_xlsx
):
    client = ApplicationAuthClient()
    client.preflight_ok = True
    client.authenticated = True
    client.expire_date = datetime.now(timezone.utc) + timedelta(hours=1)
    app = UiApplication(
        tmp_path / "state.sqlite",
        live_config(tmp_path),
        lambda _: client,
    )
    source = make_xlsx([wb_row], "one.xlsx")
    imported = app.import_bytes(source.name, source.read_bytes())
    event_id = app.events_for_import(imported["fingerprint"])[0]["event_id"]
    result = app.check_import(imported["fingerprint"], [event_id])
    assert client.prime_calls == [[wb_row["КИЗ"]]]
    assert result["checked"] == 1
    diagnostics = result["diagnostics"]
    assert diagnostics == {
        "kiz": wb_row["КИЗ"],
        "status": "IN_CIRCULATION",
        "statusEx": None,
        "withdrawReason": None,
        "ownerInn": OWN,
        "owner_match": True,
        "productGroup": "lp",
        "decision": "READY_TO_WITHDRAW",
        "reason": "SALE_IN_CIRCULATION",
        "error": None,
    }
    with EventStore(app.db_path) as store:
        assert store.count("documents") == 0
        assert store.count("document_status_history") == 0


def test_certificate_preflight_checks_gost_and_cryptopro_provider(tmp_path):
    cryptcp = tmp_path / "cryptcp.exe"
    cryptcp.write_bytes(b"placeholder")
    now = datetime.now(timezone.utc)
    payload = {
        "thumbprint": "AA11",
        "hasPrivateKey": True,
        "notBefore": (now - timedelta(days=1)).isoformat(),
        "notAfter": (now + timedelta(days=1)).isoformat(),
        "publicKeyOid": "1.2.643.7.1.1.1.1",
        "signatureOid": "1.2.643.7.1.1.3.2",
        "providerName": "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider",
    }

    def runner(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0], 0, stdout=json.dumps(payload), stderr=""
        )

    inspector = WindowsCryptoProCertificateInspector(
        "AA11", cryptcp_path=cryptcp, runner=runner
    )
    result = inspector.inspect()
    assert result["certificate_found"] is True
    assert result["thumbprint_match"] is True
    assert result["has_private_key"] is True
    assert result["not_expired"] is True
    assert result["gost_compatible"] is True
    assert result["cryptopro_provider"] is True


def test_certificate_preflight_rejects_non_cryptopro_provider(tmp_path):
    cryptcp = tmp_path / "cryptcp.exe"
    cryptcp.write_bytes(b"placeholder")
    now = datetime.now(timezone.utc)
    payload = {
        "thumbprint": "AA11",
        "hasPrivateKey": True,
        "notBefore": (now - timedelta(days=1)).isoformat(),
        "notAfter": (now + timedelta(days=1)).isoformat(),
        "publicKeyOid": "1.2.643.7.1.1.1.1",
        "signatureOid": "1.2.643.7.1.1.3.2",
        "providerName": "Some Other Provider",
    }

    def runner(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0], 0, stdout=json.dumps(payload), stderr=""
        )

    inspector = WindowsCryptoProCertificateInspector(
        "AA11", cryptcp_path=cryptcp, runner=runner
    )
    with pytest.raises(TrueApiError, match="CryptoPro provider"):
        inspector.inspect()


def test_auth_signer_uses_cryptcp_attached_der_without_pin(tmp_path):
    cryptcp = tmp_path / "cryptcp.exe"
    cryptcp.write_bytes(b"placeholder")

    class Inspector:
        def inspect(self):
            return {"ok": True}

    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        source = Path(command[command.index("-fext") - 1])
        source.with_name(source.name + ".sgn").write_bytes(b"CMS")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    signer = WindowsCryptoProAuthSigner(
        "AA11",
        cryptcp_path=cryptcp,
        inspector=Inspector(),
        runner=runner,
    )
    encoded = signer.sign_auth_challenge("challenge")
    assert base64.b64decode(encoded) == b"CMS"
    command = calls[0]
    assert "-attached" in command
    assert "-der" in command
    assert "-strict" in command
    assert "-uMy" in command
    assert "-thumbprint" in command
    assert "-fext" in command
    assert command[command.index("-fext") + 1] == ".sgn"
    assert "-pin" not in command
    for forbidden in (
        "sign_document",
        "sign_payload_for_submission",
        "submit_signed_document",
    ):
        assert not hasattr(signer, forbidden)


def test_mutation_allowlist_still_blocks_before_gost_tunnel_start(tmp_path):
    class Tunnel:
        @property
        def local_port(self):
            raise AssertionError("network/tunnel start reached")

        def diagnostics(self):
            return {}

    transport = ReadOnlyTrueApiTransport(tunnel=Tunnel())
    with pytest.raises(ProductionMutationDisabled):
        transport.request_json("POST", "/lk/documents/create", body={})
