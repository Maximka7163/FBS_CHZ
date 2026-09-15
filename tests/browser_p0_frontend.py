from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import os
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from openpyxl import Workbook
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from wbcz.models import Decision
from wbcz.write_pipeline import ExactDocumentBuilder, WriteState
from wbcz_web.auth import hash_password
from wbcz_web.models import Base, CheckRecord, ControlRun, User, WriteOperationRecord
from wbcz_web.repositories import ImportRepository, SqlAlchemyWriteOperationStore
from wbcz_web.services.imports import record_to_event


DB_URL = os.environ["WBCZ_TEST_DATABASE_URL"]
BASE_URL = os.environ.get("WBCZ_BROWSER_URL", "http://127.0.0.1:5173")
OUT = Path(os.environ.get("WBCZ_BROWSER_SCREENSHOT_DIR", "browser-artifacts"))
OWN = os.environ.get("WBCZ_OWN_INN", "1234567890")
PASSWORD = "browser-review-password-2026"
CIS_PREFIX = "010290089707781021"


def cis(label: str) -> str:
    return CIS_PREFIX + label


def prepare_database(factory) -> None:
    engine = factory.kw["bind"]
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with factory() as db:
        db.add(User(username="browser", password_hash=hash_password(PASSWORD), is_active=True, is_admin=True))
        db.commit()


def create_workbook(path: Path) -> None:
    wb = Workbook()
    sheet = wb.active
    sheet.title = "КИЗ"
    sheet.append([
        "№ задания", "Стикер", "КИЗ", "Номер чека", "Стоимость", "Валюта",
        "Номер фискального накопителя", "Дата", "Тип операции", "Признак продажи юрлицу",
    ])
    rows = [
        ("READY-W", "Продажа"),
        ("READY-R", "Возврат"),
        ("MANUAL", "Продажа"),
        ("ERROR", "Продажа"),
        ("DONE", "Продажа"),
        ("NOACTION", "Продажа"),
        ("COMPLETE", "Продажа"),
    ]
    for index, (label, operation) in enumerate(rows, start=1):
        sheet.append([
            f"T{index}", f"S{index}", cis(label), f"CHK-{index}", 1901.75, "RUB",
            "7380440903834317", f"12:34:56 {18 + index:02d}.08.2026", operation, "нет",
        ])
    wb.save(path)


def seed_visual_states(factory, import_id: str) -> None:
    with factory() as db:
        imported = ImportRepository(db).get(import_id)
        assert imported is not None
        user = db.scalar(select(User).where(User.username == "browser"))
        assert user is not None
        records = ImportRepository(db).ordered_event_records(import_id)
        assert len(records) == 7
        run = ControlRun(import_id=import_id, user_id=user.id, mode="AUTO", provider="visual-ci")
        db.add(run)
        db.flush()
        decisions = [
            (Decision.READY_TO_WITHDRAW, "SALE_IN_CIRCULATION", None),
            (Decision.READY_TO_RETURN, "RETURN_WITHDRAWN_DISTANCE", None),
            (Decision.MANUAL_REVIEW, "OWNER_MISMATCH", None),
            (Decision.ERROR, "STATE_LOOKUP_OR_NORMALIZATION_FAILED", "TrueApiError"),
            (Decision.ALREADY_DONE, "SALE_ALREADY_WITHDRAWN_DISTANCE", None),
            (Decision.NO_ACTION, "TEST_NO_ACTION", None),
            (Decision.READY_TO_WITHDRAW, "SALE_IN_CIRCULATION", None),
        ]
        for record, (decision, reason, error) in zip(records, decisions):
            event = record_to_event(record)
            if decision in {Decision.READY_TO_WITHDRAW, Decision.READY_TO_RETURN}:
                snapshot = {
                    "status": "IN_CIRCULATION" if decision is Decision.READY_TO_WITHDRAW else "WITHDRAWN",
                    "statusEx": None,
                    "withdrawReason": None if decision is Decision.READY_TO_WITHDRAW else "DISTANCE",
                    "ownerInn": OWN,
                    "productGroup": "lp",
                }
            else:
                snapshot = None
            db.add(CheckRecord(
                run_id=run.id,
                event_id=record.event_id,
                source="visual-ci",
                snapshot=snapshot,
                decision=decision.value,
                reason=reason,
                error=error,
            ))
        db.flush()
        complete_record = records[-1]
        document = ExactDocumentBuilder.from_json_value({"VISUAL_CI_ONLY": True})
        stored = SqlAlchemyWriteOperationStore(db).prepare(
            event_id=complete_record.event_id,
            decision=Decision.READY_TO_WITHDRAW,
            document_type="LK_RECEIPT",
            operation_reason="DISTANCE",
            pg="lp",
            expected_inn=OWN,
            document=document,
        )
        row = db.get(WriteOperationRecord, stored.operation_id)
        assert row is not None
        row.state = WriteState.SUCCEEDED.value
        db.commit()


def screenshot(driver, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    driver.save_screenshot(str(OUT / name))


def click_filter(driver, key: str) -> None:
    driver.find_element(By.CSS_SELECTOR, f'[data-filter="{key}"]').click()
    WebDriverWait(driver, 5).until(lambda d: d.find_element(By.CSS_SELECTOR, f'[data-filter="{key}"]').get_attribute("class").find("active") >= 0)


def main() -> None:
    engine = create_engine(DB_URL, future=True)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    prepare_database(factory)
    OUT.mkdir(parents=True, exist_ok=True)
    workbook = OUT / "browser-flow.xlsx"
    create_workbook(workbook)

    options = webdriver.ChromeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1440,950")
    driver = webdriver.Chrome(options=options)
    wait = WebDriverWait(driver, 12)
    try:
        driver.get(BASE_URL)
        wait.until(EC.visibility_of_element_located((By.ID, "login")))
        driver.find_element(By.ID, "username").send_keys("browser")
        driver.find_element(By.ID, "password").send_keys(PASSWORD)
        driver.find_element(By.CSS_SELECTOR, "#login button[type=submit]").click()
        wait.until(EC.visibility_of_element_located((By.ID, "dropzone")))
        screenshot(driver, "01-empty.png")

        file_input = driver.find_element(By.ID, "file")
        driver.execute_script("arguments[0].hidden=false; arguments[0].style.display='block';", file_input)
        file_input.send_keys(str(workbook.resolve()))
        wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, ".workspace-card")))
        screenshot(driver, "02-uploaded.png")

        import_id = parse_qs(urlparse(driver.current_url).query).get("import", [None])[0]
        assert import_id
        driver.find_element(By.ID, "check").click()
        wait.until(lambda d: "Проверяем КИЗ" in d.find_element(By.CSS_SELECTOR, ".workspace-card").text)
        screenshot(driver, "03-processing.png")

        seed_visual_states(factory, import_id)
        driver.refresh()
        wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, ".work-table")))
        wait.until(lambda d: "Готово к выводу" in d.find_element(By.CSS_SELECTOR, ".work-table").text)
        screenshot(driver, "04-mixed-ready.png")

        click_filter(driver, "ATTENTION")
        wait.until(lambda d: "Требует внимания" in d.find_element(By.CSS_SELECTOR, ".work-table").text)
        screenshot(driver, "05-manual-review.png")

        click_filter(driver, "ERROR")
        wait.until(lambda d: "Ошибка" in d.find_element(By.CSS_SELECTOR, ".work-table").text)
        screenshot(driver, "06-error.png")

        click_filter(driver, "DONE")
        wait.until(lambda d: "Выполнено" in d.find_element(By.CSS_SELECTOR, ".work-table").text)
        screenshot(driver, "07-completed.png")

        click_filter(driver, "ALL")
        bulk = driver.find_element(By.ID, "bulk-action")
        assert bulk.is_enabled()
        bulk.click()
        wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, ".confirm-modal")))
        modal_text = driver.find_element(By.CSS_SELECTOR, ".confirm-modal").text
        assert "2" in modal_text and "Выводов" in modal_text and "Возвратов" in modal_text
        screenshot(driver, "08-bulk-confirmation.png")
        driver.find_element(By.ID, "confirm-bulk").click()
        wait.until(lambda d: "Ожидает агента" in d.find_element(By.CSS_SELECTOR, ".work-table").text)
        screenshot(driver, "09-after-bulk.png")

        history = driver.find_element(By.ID, "history")
        driver.execute_script("arguments[0].scrollIntoView({block:'start'});", history)
        screenshot(driver, "10-history.png")

        driver.set_window_size(1120, 760)
        driver.execute_script("window.scrollTo(0,0)")
        screenshot(driver, "11-narrow-desktop.png")
        assert driver.execute_script("return document.documentElement.scrollWidth") <= 1120

        page_source = driver.page_source
        assert "WBCZ_AGENT_MACHINE_TOKEN" not in page_source
        assert "markirovka.crpt.ru" not in page_source
        assert "Ввод в оборот" not in page_source
        assert "Возврат в оборот" in page_source
        print("BROWSER_P0_FLOW=PASS")
        print(f"SCREENSHOTS={OUT.resolve()}")
    finally:
        driver.quit()
        engine.dispose()


if __name__ == "__main__":
    main()
