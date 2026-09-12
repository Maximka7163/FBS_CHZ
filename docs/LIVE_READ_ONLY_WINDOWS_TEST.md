# Первый LIVE READ-ONLY тест на Windows

Эта инструкция относится только к v0.4. В этой версии приложение умеет аутентифицироваться в production True API с помощью УКЭП и читать состояния КИЗ. Создание, подписание и отправка документов в ГИС МТ отсутствуют.

## 1. Что установить

Нужно:

- Windows 10/11;
- CryptoPro CSP с действующей лицензией;
- сертификат вашей УКЭП, установленный вместе с приватным ключом в хранилище текущего пользователя Windows (`CurrentUser\\My`);
- Python 3.12;
- Node.js 20 или 22;
- исходники ветки `ui/v0.3-first-real-ui`.

Браузерный CryptoPro-плагин для этой реализации не нужен. Подпись authentication challenge выполняется backend-процессом через сертификат в Windows certificate store и криптопровайдер CryptoPro.

Не экспортируйте приватный ключ. Не загружайте контейнер ключа, PIN, пароль или токены в ChatGPT, GitHub, облако или файлы проекта.

## 2. Проверить сертификат

Откройте обычный PowerShell от своего пользователя Windows и выполните:

```powershell
Get-ChildItem Cert:\CurrentUser\My |
  Where-Object { $_.HasPrivateKey } |
  Select-Object Subject, Thumbprint, NotAfter, HasPrivateKey
```

Найдите нужный сертификат УКЭП вашей организации.

Ожидается:

- `HasPrivateKey = True`;
- срок `NotAfter` ещё не истёк;
- `Subject` соответствует нужной организации/ИП.

Скопируйте только `Thumbprint`. Приватный ключ копировать или экспортировать не нужно.

## 3. Установить Python-зависимости

В корне проекта откройте PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[ui,test]"
```

## 4. Установить frontend-зависимости

Во втором PowerShell:

```powershell
cd frontend
npm install
npm run typecheck
npm run build
```

После проверки вернитесь в режим разработки:

```powershell
npm run dev
```

Ожидаемый адрес frontend: `http://127.0.0.1:5173`.

## 5. Включить LIVE READ-ONLY

В PowerShell, из которого будет запущен backend, задайте переменные. Подставьте свой ИНН и Thumbprint:

```powershell
$env:WBCZ_TRUE_API_MODE="live-read-only"
$env:WBCZ_PARTICIPANT_INN="ВАШ_ИНН"
$env:WBCZ_UKEP_THUMBPRINT="THUMBPRINT_СЕРТИФИКАТА"
$env:WBCZ_LIVE_AUDIT_LOG="$PWD\live_true_api.jsonl"
```

Не задавайте другой `WBCZ_TRUE_API_BASE_URL`. v0.4 разрешает только официальный production base URL True API.

Настройка МОД (`FIAS_ID`/`KPP`) для этой проверки не нужна: v0.4 не создаёт документы.

## 6. Запустить backend

В том же PowerShell:

```powershell
.\.venv\Scripts\python.exe -m wbcz_ui --db .\wbcz-live-readonly.sqlite
```

Ожидается запуск на `http://127.0.0.1:8765`.

В отдельном PowerShell можно проверить режим:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/api/status | Format-List
```

Ожидаемые признаки:

```text
mode              : live-read-only
true_api          : True
auth_signing      : True
document_signing  : False
submission        : False
product_group     : lp
```

Если `document_signing` или `submission` неожиданно `True`, тест прекратить.

## 7. Открыть приложение

После `npm run dev` откройте Edge/Chrome:

```text
http://127.0.0.1:5173
```

В верхней части интерфейса должна быть компактная метка:

**«Реальный контроль ЧЗ · отправка отключена»**

Рабочей кнопки «Отправить», «Выполнить» или подписи production-документа быть не должно.

## 8. Загрузить WB XLSX

Нажмите область загрузки или перетащите `REF_WB_archive_9.xlsx`.

Ожидается:

- 238 событий;
- 238 уникальных КИЗ;
- 76 продаж;
- 162 возврата;
- 0 rejected rows.

Загрузка XLSX сама по себе не обращается к True API и ничего не подписывает.

## 9. Первый LIVE-тест — только один заранее выбранный КИЗ

1. Возьмите один КИЗ, состояние которого вы можете вручную проверить в Честном знаке/MarkZnak.
2. В поле поиска вставьте этот полный КИЗ.
3. Отметьте найденную строку чекбоксом.
4. В селекторе объёма проверки выберите **«1 КИЗ»**.
5. Убедитесь, что в интерфейсе всё ещё написано **«Реальный контроль ЧЗ · отправка отключена»**.
6. Нажмите **«Проверить КИЗ»**.

До этого нажатия production True API не вызывается.

## 10. Что происходит с УКЭП

При первом live-запросе backend выполняет только authentication flow:

1. `GET /auth/key`;
2. получает `uuid` и challenge `data`;
3. передаёт только challenge в локальный Windows/CryptoPro signer;
4. отправляет подпись challenge в `POST /auth/simpleSignIn`;
5. получает временный production token;
6. выполняет `POST /api/v3/true-api/cises/info?pg=lp` для выбранного КИЗ.

УКЭП **не подписывает документ вывода/возврата**. В v0.4 такого callable пути нет.

CryptoPro/Windows может показать системное окно доступа к контейнеру или ввода PIN. В зависимости от настроек контейнера окно может и не появиться, если доступ уже разрешён/закэширован.

Если окно появляется:

- ожидайте выбор/использование вашего сертификата и доступ к его приватному ключу;
- PIN вводите только в системное/CryptoPro окно;
- приложение не просит PIN в браузере или командной строке;
- не экспортируйте приватный ключ.

Системное окно может не показывать человекочитаемое назначение challenge. Гарантия назначения обеспечивается архитектурой v0.4: signer имеет только `sign_auth_challenge`, а production transport разрешает только auth и `cises/info`.

## 11. Проверить результат одного КИЗ

После успешного запроса строка должна получить backend-рекомендацию, например:

- «Нужно вывести»;
- «Нужно вернуть»;
- «Уже обработано»;
- «Требует проверки»;
- «Ошибка».

Не интерпретируйте `MANUAL_REVIEW` как ошибку программы: это штатный fail-safe результат, например при отсутствии чека, несовпадении владельца или неизвестном состоянии.

## 12. Проверить audit

В PowerShell:

```powershell
Get-Content .\live_true_api.jsonl -Tail 20
```

Для первого запроса ожидаются metadata-записи с endpoint:

```text
/auth/key
/auth/simpleSignIn
/cises/info
```

и полями вроде:

- `timestamp`;
- `mode: LIVE_READ_ONLY`;
- `cis_count`;
- `http_status`;
- `request_id`, если сервер его вернул.

В audit не должны попадать token, полная auth signature, private key или PIN.

## 13. Сравнить с Честным знаком / MarkZnak

Для того же КИЗ вручную откройте его в привычном интерфейсе Честного знака/MarkZnak и сравните минимум:

- текущий статус: в обороте / выбыл;
- если выбыл — причина выбытия;
- владельца;
- контекст товарной группы одежды (`lp`).

Затем сравните с рекомендацией приложения и исходной операцией WB.

Если состояние расходится, не переходите к массовой проверке. Сохраните безопасный audit metadata и остановите тест.

## 14. Проверить небольшой набор

Только после успешного теста одного КИЗ:

1. выберите несколько строк чекбоксами;
2. в селекторе объёма выберите **«Выбранные»**;
3. нажмите **«Проверить КИЗ»**;
4. проверьте несколько результатов вручную.

## 15. Проверить весь файл

Только после успешного малого набора:

1. в селекторе выберите **«Весь файл»**;
2. нажмите **«Проверить КИЗ»**;
3. дождитесь завершения;
4. при необходимости выберите строки и нажмите **«Проверить состав»**.

Preview — только расчёт состава по сохранённым backend-решениям. Он не создаёт и не отправляет документы.

## 16. Как остановить LIVE режим

Остановите backend `Ctrl+C`. Затем в новом PowerShell не задавайте LIVE-переменные либо выполните:

```powershell
Remove-Item Env:WBCZ_TRUE_API_MODE -ErrorAction SilentlyContinue
Remove-Item Env:WBCZ_PARTICIPANT_INN -ErrorAction SilentlyContinue
Remove-Item Env:WBCZ_UKEP_THUMBPRINT -ErrorAction SilentlyContinue
Remove-Item Env:WBCZ_LIVE_AUDIT_LOG -ErrorAction SilentlyContinue
```

После обычного запуска `/api/status` должен показывать `offline-dry-run`.

## Safety guarantee v0.4

Подключение УКЭП само по себе ничего не выводит и не возвращает в оборот.

В v0.4 физически доступны только:

- `GET /api/v3/true-api/auth/key`;
- `POST /api/v3/true-api/auth/simpleSignIn`;
- `POST /api/v3/true-api/cises/info?pg=lp`.

Любая другая production route блокируется локально исключением `ProductionMutationDisabled` до HTTP-запроса. Production document signing, `LK_RECEIPT`, `LP_RETURN`, cancellation и submission retry в v0.4 отсутствуют.
