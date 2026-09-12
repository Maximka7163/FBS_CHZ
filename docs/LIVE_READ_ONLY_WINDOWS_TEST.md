# v0.4 LIVE READ-ONLY: первый тест на Windows

Эта инструкция относится только к ветке `ui/v0.3-first-real-ui` и v0.4 LIVE READ-ONLY. Она специально разделяет проверку ГОСТ TLS, авторизацию и чтение одного КИЗ на три независимых действия.

В v0.4 отсутствуют production document signing, `LK_RECEIPT`, `LP_RETURN`, `/lk/documents/create`, cancellation и retry submission. Любая production route вне read-only allowlist блокируется локально до network I/O.

## Что должно быть установлено

Нужно:

- Windows 10/11;
- КриптоПро CSP 5.0 с компонентом `stunnel_msspi.exe` из установленного комплекта КриптоПро CSP;
- `cryptcp.exe` из КриптоПро CSP;
- действующий сертификат УКЭП в `CurrentUser\\My`, связанный с приватным ключом КриптоПро;
- Python 3.12;
- Node.js 20/22, пока frontend запускается через Vite;
- исходники ветки `ui/v0.3-first-real-ui`.

Не используйте произвольный OpenSSL/stunnel вместо `stunnel_msspi.exe` КриптоПро. Не отключайте проверку сертификата сервера. Не экспортируйте приватный ключ и не передавайте PIN приложению, в GitHub, ChatGPT или облако.

## Подготовка сертификата

Откройте обычный PowerShell от своего пользователя Windows:

```powershell
Get-ChildItem Cert:\CurrentUser\My |
  Where-Object { $_.HasPrivateKey } |
  Select-Object Subject, Thumbprint, NotAfter, HasPrivateKey
```

Найдите нужную УКЭП. Ожидается `HasPrivateKey = True`, срок действия не истёк, Subject относится к нужной организации/ИП. Скопируйте только Thumbprint.

Приложение дополнительно само проверит перед авторизацией:

- сертификат найден по точному Thumbprint;
- `HasPrivateKey = True`;
- срок действия сертификата;
- GOST public-key OID;
- привязку закрытого ключа к провайдеру CryptoPro;
- наличие `cryptcp.exe`.

PIN и содержимое приватного ключа при этой диагностике не читаются.

## Установка приложения

В корне проекта:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[ui,test]"
```

Frontend:

```powershell
cd frontend
npm install
npm run typecheck
npm run build
npm run dev
```

Ожидаемый frontend: `http://127.0.0.1:5173`.

## Включение LIVE READ-ONLY

Откройте отдельный PowerShell в корне проекта. Подставьте свой ИНН и Thumbprint:

```powershell
$env:WBCZ_TRUE_API_MODE="live-read-only"
$env:WBCZ_PARTICIPANT_INN="ВАШ_ИНН"
$env:WBCZ_UKEP_THUMBPRINT="ВАШ_THUMBPRINT"
$env:WBCZ_LIVE_AUDIT_LOG="$PWD\live_true_api.jsonl"
```

Обычно пути к CryptoPro определяются автоматически. Если нет, задайте их явно, используя именно файлы установленного КриптоПро CSP:

```powershell
$env:WBCZ_CRYPTOPRO_STUNNEL="C:\Program Files\Crypto Pro\CSP\stunnel_msspi.exe"
$env:WBCZ_CRYPTOPRO_CRYPTCP="C:\Program Files\Crypto Pro\CSP\cryptcp.exe"
```

Не меняйте `WBCZ_TRUE_API_BASE_URL`: v0.4 разрешает только production `https://markirovka.crpt.ru/api/v3/true-api`.

Запустите backend:

```powershell
.\.venv\Scripts\python.exe -m wbcz_ui --db .\wbcz-live-readonly.sqlite
```

Перед тестом проверьте:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/api/status | Format-List
```

Ожидается минимум:

```text
mode             : live-read-only
true_api         : True
auth_signing     : True
document_signing : False
submission       : False
product_group    : lp
```

Если `document_signing` или `submission` вдруг `True`, остановите тест.

---

## Шаг 1 — TLS preflight

1. Откройте Edge/Chrome: `http://127.0.0.1:5173`.
2. Вверху должно быть: **«Реальный контроль ЧЗ · отправка отключена»**.
3. Нажмите **«Проверить подключение»**.

На этом шаге приложение имеет право выполнить только:

```text
GET /api/v3/true-api/auth/key
```

Что происходит технически:

- Python открывает только локальный HTTP-сокет `127.0.0.1`;
- production TLS устанавливает `stunnel_msspi.exe` КриптоПро CSP через MSSPI/SSPI;
- production leg принудительно ограничен TLS 1.2 и GOST-only cipher list;
- `verify=2`, `checkHost=markirovka.crpt.ru` и SNI включены;
- после каждого production-запроса приложение требует явный MSSPI negotiated-session marker `SECPKG_ATTR_CIPHER_INFO: CipherSuite: c100/c101/c102`;
- строка конфигурации `ciphers = GOST...` сама по себе доказательством handshake не считается;
- никакой signer на этом шаге не вызывается.

Ожидаемый UI:

**«CryptoPro TLS доступен · True API доступен · УКЭП готова · challenge получен»**

Системного окна подписи/PIN на этом шаге быть не должно. Если оно неожиданно появилось — остановитесь и не переходите дальше.

Если серверный сертификат не прошёл проверку, negotiated GOST CipherSuite нельзя однозначно подтвердить по MSSPI diagnostics или `stunnel_msspi.exe` недоступен, preflight завершается `GostTlsUnavailable`/понятной ошибкой и не делает fallback на обычный HTTPS.

Для диагностики успешного TLS preflight ожидается именно negotiated-session запись вида:

```text
SECPKG_ATTR_CIPHER_INFO: CipherSuite: c100, ...
```

Также допускаются документированные для используемого CryptoPro TLS 1.2 `c101` и `c102`. Любое простое упоминание слова `GOST`, включая строку настройки cipher list, намеренно игнорируется как proof.

## Шаг 2 — авторизация

После успешного preflight нажмите **«Авторизоваться»**.

Приложение выполняет только:

```text
GET  /api/v3/true-api/auth/key
local CryptoPro cryptcp attached CMS signature of challenge
POST /api/v3/true-api/auth/simpleSignIn
```

В `/auth/simpleSignIn` отправляется `unitedToken=true`. После ответа сохраняются только временные runtime token/expireDate; token и подпись не пишутся в audit.

`cryptcp.exe` выбирает сертификат по вашему Thumbprint в `CurrentUser\My`, создаёт присоединённую DER/strict CMS-подпись authentication challenge и обращается к закрытому ключу через CryptoPro provider. Приватный ключ не экспортируется. В командной строке приложения PIN не передаётся.

Если контейнер требует PIN, его вводите только в системном окне CryptoPro. Не вводите PIN в браузер, PowerShell-команду или файл конфигурации.

Ожидаемый UI после успешного ответа:

**«Авторизация успешна. Отправка документов отключена.»**

После авторизации UI автоматически переводит безопасный первый сценарий в:

```text
Режим: Контроль
Scope: 1 КИЗ
```

Важно: успешная авторизация сама по себе **не вызывает `/cises/info`**, не создаёт preview и не создаёт production documents.

## Шаг 3 — CONTROL одного КИЗ

Только после успешной авторизации:

1. Загрузите `REF_WB_archive_9.xlsx`, если файл ещё не открыт.
2. Возьмите один заранее выбранный КИЗ, который сможете вручную проверить в Честном знаке/MarkZnak.
3. Вставьте его полный КИЗ в поиск так, чтобы в таблице осталась нужная строка.
4. Убедитесь: режим **«Контроль»**, scope **«1 КИЗ»**. В режиме «Контроль» чекбоксы операций специально скрыты.
5. Нажмите **«Проверить КИЗ»**.

Теперь разрешён ровно один production read:

```text
POST /api/v3/true-api/cises/info?pg=lp
```

После ответа над таблицей появится **«Диагностика одного КИЗ»**. Она показывает только нормализованные backend-данные:

```text
status
statusEx
withdrawReason
ownerInn + совпадает/не совпадает
productGroup
backend decision
reason code
```

Token, auth signature и raw True API response не выводятся во frontend.

## Шаг 4 — сравнение с Честным знаком / MarkZnak

Для того же КИЗ вручную откройте карточку/контроль КИЗ в Честном знаке или MarkZnak и сравните:

- статус: в обороте / выбыл;
- особое состояние, если отображается;
- причину выбытия;
- владельца;
- товарную группу;
- исходное событие WB и backend decision/reason code.

Если есть расхождение — не запускайте массовую проверку. Сохраните только безопасный `live_true_api.jsonl` и остановите backend.

Только после совпадения одного КИЗ можно отдельно проверить небольшой выбранный набор. И только после этого — весь файл.

## Audit

Проверить metadata audit:

```powershell
Get-Content .\live_true_api.jsonl -Tail 30
```

Допустимые поля:

- timestamp;
- `mode = LIVE_READ_ONLY`;
- method/endpoint;
- число КИЗ;
- HTTP status;
- request/correlation ID, если сервер его вернул;
- безопасная error metadata.

Не должны логироваться token, auth signature, private key, PIN или секретные данные сертификата.

## Production safety boundary v0.4

Через production transport разрешены только:

```text
GET  /api/v3/true-api/auth/key
POST /api/v3/true-api/auth/simpleSignIn
POST /api/v3/true-api/cises/info?pg=lp
```

Любой другой endpoint, включая `/lk/documents/create`, `LK_RECEIPT`, `LP_RETURN`, cancellation и retry, вызывает `ProductionMutationDisabled` **до запуска network I/O**.

Подключение УКЭП само по себе ничего не выводит и не возвращает в оборот. УКЭП v0.4 используется только для authentication challenge.
