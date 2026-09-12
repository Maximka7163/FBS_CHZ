from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from urllib.request import urlopen

from playwright.sync_api import Page, sync_playwright


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
API_URL = "http://127.0.0.1:8765"
WEB_URL = "http://127.0.0.1:5173"


def wait_url(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        try:
            with urlopen(url, timeout=1.0) as response:
                if 200 <= response.status < 500:
                    return
        except Exception as exc:  # pragma: no cover - integration wait loop
            last = exc
        time.sleep(0.2)
    raise RuntimeError(f"Timed out waiting for {url}: {last}")


def stop_process_tree(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:  # pragma: no cover - Windows CI is the acceptance target
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()


def start_backend(db: Path, log: Path) -> subprocess.Popen[bytes]:
    kwargs: dict[str, object] = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:  # pragma: no cover
        kwargs["start_new_session"] = True
    handle = log.open("wb")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "wbcz_ui",
            "--db",
            str(db),
            "--host",
            "127.0.0.1",
            "--port",
            "8765",
        ],
        cwd=ROOT,
        stdout=handle,
        stderr=subprocess.STDOUT,
        **kwargs,
    )
    process._wbcz_log_handle = handle  # type: ignore[attr-defined]
    wait_url(f"{API_URL}/api/status")
    return process


def start_frontend(log: Path) -> subprocess.Popen[bytes]:
    kwargs: dict[str, object] = {}
    if os.name == "nt":
        command = [
            "cmd.exe", "/d", "/s", "/c",
            "npm", "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173",
        ]
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:  # pragma: no cover
        npm = shutil.which("npm") or "npm"
        command = [npm, "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173"]
        kwargs["start_new_session"] = True
    handle = log.open("wb")
    process = subprocess.Popen(
        command,
        cwd=FRONTEND,
        stdout=handle,
        stderr=subprocess.STDOUT,
        **kwargs,
    )
    process._wbcz_log_handle = handle  # type: ignore[attr-defined]
    wait_url(WEB_URL)
    return process


def close_log(process: subprocess.Popen[bytes] | None) -> None:
    handle = getattr(process, "_wbcz_log_handle", None)
    if handle is not None:
        handle.close()


def browser_json(page: Page, path: str) -> object:
    return page.evaluate(
        """async (path) => {
          const r = await fetch(path);
          if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
          return await r.json();
        }""",
        path,
    )


def screenshot(page: Page, out: Path, filename: str) -> None:
    page.screenshot(path=str(out / filename), full_page=False)


def assert_counts(imported: dict[str, object]) -> None:
    expected = {
        "event_count": 238,
        "unique_kiz": 238,
        "sales": 76,
        "returns": 162,
        "dated": 68,
        "undated": 170,
        "rejected_rows": 0,
    }
    for key, value in expected.items():
        assert imported[key] == value, (key, imported[key], value)


def main() -> int:
    parser = argparse.ArgumentParser(description="Real Windows browser E2E for WB FBS UI")
    parser.add_argument("--ref", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "e2e_artifacts")
    args = parser.parse_args()

    ref = args.ref.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    db = out / "windows-e2e.sqlite"
    for path in (db, Path(str(db) + "-wal"), Path(str(db) + "-shm")):
        path.unlink(missing_ok=True)

    frontend_source = "\n".join(
        p.read_text(encoding="utf-8") for p in (FRONTEND / "src").glob("*.ts")
    )
    assert "localStorage" not in frontend_source
    assert "sessionStorage" not in frontend_source
    for forbidden in ("withdrawReason", "ownerInn", "statusEx", "FakeTrueApiClient", "control_engine"):
        assert forbidden not in frontend_source, forbidden
    ui_backend_source = "\n".join(
        p.read_text(encoding="utf-8") for p in (ROOT / "src" / "wbcz_ui").glob("*.py")
    )
    for forbidden in (
        "from wbcz.signing", "from wbcz.submission", "from wbcz.document_builder",
        ".submit(", ".sign(", "register_document(",
    ):
        assert forbidden not in ui_backend_source, forbidden

    backend: subprocess.Popen[bytes] | None = None
    frontend: subprocess.Popen[bytes] | None = None
    console_errors: list[str] = []
    page_errors: list[str] = []
    request_failures: list[str] = []
    result: dict[str, object] = {}

    try:
        backend = start_backend(db, out / "backend.log")
        frontend = start_frontend(out / "frontend.log")

        with sync_playwright() as pw:
            browser_kind = "msedge"
            try:
                browser = pw.chromium.launch(channel="msedge", headless=True)
            except Exception:
                browser_kind = "playwright-chromium"
                browser = pw.chromium.launch(headless=True)
            result["browser"] = browser_kind
            result["browser_version"] = browser.version
            context = browser.new_context(viewport={"width": 1440, "height": 900})
            page = context.new_page()
            page.on(
                "console",
                lambda msg: console_errors.append(msg.text) if msg.type == "error" else None,
            )
            page.on("pageerror", lambda exc: page_errors.append(str(exc)))
            page.on(
                "requestfailed",
                lambda req: request_failures.append(f"{req.method} {req.url}: {req.failure}"),
            )

            page.goto(WEB_URL, wait_until="networkidle")
            page.wait_for_selector("#drop")
            assert page.locator("text=Последние файлы").count() == 1
            assert page.locator("text=Загруженных файлов пока нет").count() == 1
            assert page.evaluate("localStorage.length") == 0

            page.set_input_files("#file", str(ref))
            page.wait_for_selector(".events tbody tr")
            page.wait_for_function("document.querySelector('#shown')?.textContent?.includes('238 из 238')")
            history = browser_json(page, "/api/imports?limit=10")
            assert isinstance(history, list) and len(history) == 1
            fingerprint = history[0]["fingerprint"]
            imported = browser_json(page, f"/api/imports/{fingerprint}")
            assert isinstance(imported, dict)
            assert_counts(imported)

            page.click("#replace")
            page.wait_for_selector(".history tbody tr")
            screenshot(page, out, "01_initial_with_history.png")

            page.locator("[data-open]").first.click()
            page.wait_for_selector(".events tbody tr")
            page.wait_for_function("document.querySelector('#shown')?.textContent?.includes('238 из 238')")
            screenshot(page, out, "02_file_loaded_table.png")

            page.evaluate("document.querySelector('#check').click()")
            page.wait_for_function(
                "document.querySelector('#check')?.textContent?.includes('Проверяем')",
                timeout=3000,
            )
            screenshot(page, out, "03_checking.png")
            page.wait_for_function(
                "document.querySelector('#check')?.textContent?.includes('Повторить проверку')",
                timeout=30000,
            )
            events = browser_json(page, f"/api/imports/{fingerprint}/events")
            assert isinstance(events, list) and len(events) == 238
            decisions = Counter(event["decision"] for event in events)
            assert decisions == Counter({
                "READY_TO_WITHDRAW": 64,
                "READY_TO_RETURN": 140,
                "ALREADY_DONE": 20,
                "MANUAL_REVIEW": 9,
                "ERROR": 5,
            }), decisions
            screenshot(page, out, "04_checked.png")

            page.check("#all")
            page.wait_for_selector(".operation-bar")
            op_text = page.locator(".operation-bar").inner_text()
            for number in ("238", "204", "64", "140", "34"):
                assert number in op_text, op_text
            screenshot(page, out, "05_selection_operation_bar.png")
            page.click("#preview")
            page.wait_for_selector(".preview")
            preview_text = page.locator(".preview").inner_text()
            for number in ("204", "64", "140", "34"):
                assert number in preview_text, preview_text
            screenshot(page, out, "06_operation_preview.png")

            page.uncheck("#all")
            page.select_option("#filter", "MANUAL_REVIEW")
            assert page.locator("#rows > tr:not(.detail-row)").count() == 9
            screenshot(page, out, "07_manual_review.png")
            page.select_option("#filter", "ERROR")
            assert page.locator("#rows > tr:not(.detail-row)").count() == 5
            screenshot(page, out, "08_error.png")

            page.select_option("#filter", "all")
            page.set_viewport_size({"width": 1280, "height": 800})
            screenshot(page, out, "09_1280x800.png")
            page.set_viewport_size({"width": 1024, "height": 640})
            screenshot(page, out, "10_1024x640.png")

            page.set_viewport_size({"width": 1440, "height": 900})
            page.click("#replace")
            page.wait_for_selector("#file")
            page.set_input_files("#file", str(ref))
            page.wait_for_selector(".events tbody tr")
            repeated = browser_json(page, f"/api/imports/{fingerprint}")
            assert isinstance(repeated, dict)
            page.click("#replace")
            page.wait_for_selector(".history tbody tr")
            history_after_repeat = browser_json(page, "/api/imports?limit=10")
            assert isinstance(history_after_repeat, list) and len(history_after_repeat) >= 2
            latest = history_after_repeat[0]
            assert latest["repeated"] is True
            assert latest["new_events"] == 0
            assert latest["duplicate_events"] == 238
            assert "Повторно загружен · новых 0" in page.locator(".history tbody tr").first.inner_text()

            stop_process_tree(backend)
            close_log(backend)
            backend = start_backend(db, out / "backend-restarted.log")
            page.reload(wait_until="networkidle")
            page.wait_for_selector(".history tbody tr")
            persisted_history = browser_json(page, "/api/imports?limit=10")
            assert isinstance(persisted_history, list) and len(persisted_history) >= 2
            page.locator("[data-open]").first.click()
            page.wait_for_selector(".events tbody tr")
            persisted_events = browser_json(page, f"/api/imports/{fingerprint}/events")
            assert isinstance(persisted_events, list) and len(persisted_events) == 238
            assert sum(event["occurred_at"] is None for event in persisted_events) == 170
            assert page.evaluate("localStorage.length") == 0

            browser.close()

        connection = sqlite3.connect(db)
        try:
            sqlite_values = {
                "events": connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                "null_occurred_at": connection.execute(
                    "SELECT COUNT(*) FROM events WHERE occurred_at IS NULL"
                ).fetchone()[0],
                "documents": connection.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
                "document_status_history": connection.execute(
                    "SELECT COUNT(*) FROM document_status_history"
                ).fetchone()[0],
            }
        finally:
            connection.close()
        assert sqlite_values == {
            "events": 238,
            "null_occurred_at": 170,
            "documents": 0,
            "document_status_history": 0,
        }, sqlite_values

        assert console_errors == [], console_errors
        assert page_errors == [], page_errors
        assert request_failures == [], request_failures

        result.update({
            "platform": platform.platform(),
            "python": sys.version,
            "ref": str(ref),
            "import": imported,
            "decisions": dict(decisions),
            "preview": {"included": 204, "withdraw": 64, "returns": 140, "excluded": 34},
            "repeat": latest,
            "sqlite_after_restart": sqlite_values,
            "console_errors": console_errors,
            "page_errors": page_errors,
            "request_failures": request_failures,
            "local_storage_used": False,
            "production_true_api": False,
            "production_signing": False,
            "production_submission": False,
        })
        (out / "e2e-report.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    finally:
        stop_process_tree(frontend)
        stop_process_tree(backend)
        close_log(frontend)
        close_log(backend)


if __name__ == "__main__":
    raise SystemExit(main())
