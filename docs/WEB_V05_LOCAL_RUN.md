# Web v0.5 local run

Requirements: Python 3.12, Node 20/22 and Docker Compose.

1. Start the isolated development PostgreSQL:

```powershell
docker compose -f docker-compose.dev.yml up -d postgres
```

2. Install and migrate:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[web,test]"
$env:WBCZ_ENV="development"
$env:WBCZ_DATABASE_URL="postgresql+psycopg://wbcz:wbcz_dev@127.0.0.1:5433/wbcz"
$env:WBCZ_OWN_INN="1234567890"
.\.venv\Scripts\alembic.exe upgrade head
```

3. Create the first user. Password is requested interactively:

```powershell
.\.venv\Scripts\python.exe -m wbcz_web.admin create-user owner --admin
.\.venv\Scripts\python.exe -m wbcz_web.admin list-users
```

4. Backend:

```powershell
.\.venv\Scripts\python.exe -m wbcz_web --host 127.0.0.1 --port 8765
```

5. Frontend in another terminal:

```powershell
cd frontend
npm install
npm run typecheck
npm run dev
```

Open `http://127.0.0.1:5173`, sign in, upload the WB XLSX, run CONTROL/AUTO/WITHDRAW_ONLY/RETURN_ONLY, and inspect backend decisions/preview. No real True API call or marking-document submission can occur in v0.5.
