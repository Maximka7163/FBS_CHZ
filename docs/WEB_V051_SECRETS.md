# Web v0.5.1 — secrets handling

## Secrets in production

`/opt/sellari-marking/runtime/.env.production` contains production configuration and must be `0600`. It is not a repository file.

Secret values include at least:

- `WBCZ_POSTGRES_PASSWORD`;
- password embedded in `WBCZ_DATABASE_URL`;
- user passwords entered interactively.

Generate a database password on the server with an approved password generator, for example `openssl rand -base64 32`, then URL-encode it before embedding it in `WBCZ_DATABASE_URL` if necessary. Do not paste generated secrets into source control or chat.

## Owner password

The first owner is created only with:

```bash
docker compose --env-file /opt/sellari-marking/runtime/.env.production -f docker-compose.prod.yml run --rm marking-backend wbcz-web-admin create-user owner --admin
```

Password input is interactive via `getpass`. There is no password environment variable or password CLI argument.

Passwords are stored as Argon2id hashes. Session tokens are random opaque values and only their SHA-256 hashes are stored in PostgreSQL. The session cookie is `HttpOnly`, `Secure` in production and `SameSite=Lax`. CSRF protection remains active.

## Not present in this package

Do not add the following to the VPS, compose file, env file or repository for v0.5.1:

- CryptoPro containers/configuration;
- УКЭП private keys or PINs;
- production True API tokens/certificates;
- Windows Bridge credentials;
- Sellari or «Коллег» credentials.

TLS private keys/certificate lifecycle belong to the host nginx operator and are intentionally absent from this package.
